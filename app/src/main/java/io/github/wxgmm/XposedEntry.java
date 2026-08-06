package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * WeChatGM —— LibXposed API 102 模块
 *
 * 目标：微信小游戏（AppBrand JS 运行时，V8）GM 面板注入
 * 策略：探测 + 通用 hook
 *   1) hook ClassLoader.loadClass 记录 appbrand/js 相关类名（帮助定位真实类名）
 *   2) 尝试一组候选 JS 引擎类，hook 其 evaluate 方法
 *   3) evaluate 触发后注入 payload：等 Cocos System 就绪 → hook LayerManager.open → 打开 UITest(UIID=4)
 *
 * 说明：微信 8.0.76 内部类名混淆且随版本变化，第一版以"探测为主"，
 *       运行后在 LSPosed 日志中查看 [WxGM] 输出的真实类名，再精确定位。
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";
    private static final String TARGET_PACKAGE = "com.tencent.mm";

    /** 候选 JS 引擎类（版本相关，找不到会跳过并记录日志） */
    private static final String[] CANDIDATE_CLASSES = {
            "com.tencent.mm.plugin.appbrand.jsruntime.AppBrandJsRuntime",
            "com.tencent.mm.plugin.appbrand.jsruntime.JsRuntime",
            "com.tencent.mm.plugin.appbrand.jsruntime.e",
            "com.tencent.mm.appbrand.v8.V8JsRuntime",
            "com.tencent.mm.plugin.appbrand.jsapi.v8.V8Engine",
    };

    /** 候选 evaluate 方法名 */
    private static final String[] EVALUATE_METHODS = {
            "evaluateJavascript", "evaluate", "evaluateJs", "evaluateScript", "eval"
    };

    /** 注入一次即可 */
    private static final AtomicBoolean INJECTED = new AtomicBoolean(false);
    /** 记录已 hook 的类，避免重复 */
    private static final Set<String> HOOKED_CLASSES = new HashSet<>();

    private static volatile Object sEngineInstance;   // JS 引擎实例
    private static volatile Method sEvaluateMethod;   // 引擎的 evaluate 方法
    private static ClassLoader sAppClassLoader;

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "module loaded, pid=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "WeChat loaded, first=" + param.isFirstPackage());
        sAppClassLoader = param.getDefaultClassLoader();

        // 1) 探测：hook ClassLoader.loadClass 记录 appbrand/v8/js 相关类名
        hookClassLoaderProbe();
        // 2) 尝试候选类
        for (String cn : CANDIDATE_CLASSES) {
            tryHookClass(cn);
        }
    }

    // ------------------------------------------------------------------
    // 探测：记录微信加载的 JS 运行时相关类名
    // ------------------------------------------------------------------
    private void hookClassLoaderProbe() {
        try {
            Method loadClass = ClassLoader.class.getDeclaredMethod("loadClass", String.class);
            hook(loadClass)
                    .setPriority(XposedInterface.PRIORITY_DEFAULT)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        Object result = chain.proceed();
                        try {
                            String name = String.valueOf(chain.getArg(0));
                            if (isJsRuntimeClass(name) && HOOKED_CLASSES.add(name)) {
                                log(Log.INFO, TAG, "[probe] loaded class: " + name);
                                if (result instanceof Class) {
                                    tryHookClassMethods((Class<?>) result);
                                }
                            }
                        } catch (Throwable ignored) {
                        }
                        return result;
                    });
            log(Log.INFO, TAG, "ClassLoader.loadClass hooked for probe");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "hookClassLoaderProbe failed: " + t);
        }
    }

    private boolean isJsRuntimeClass(String name) {
        if (name == null || name.isEmpty()) return false;
        String lower = name.toLowerCase();
        return (lower.contains("appbrand") || lower.contains("jsruntime") || lower.contains("jsbridge"))
                && (lower.contains("v8") || lower.contains("jscore") || lower.contains("javascript")
                || lower.contains("evaluate") || lower.contains("runtime") || lower.contains("js"));
    }

    // ------------------------------------------------------------------
    // 尝试 hook 候选类
    // ------------------------------------------------------------------
    private void tryHookClass(String className) {
        try {
            Class<?> clazz = Class.forName(className, false, sAppClassLoader);
            log(Log.INFO, TAG, "[candidate] found: " + className);
            tryHookClassMethods(clazz);
        } catch (Throwable t) {
            log(Log.DEBUG, TAG, "[candidate] skip " + className + ": " + t.getMessage());
        }
    }

    private void tryHookClassMethods(Class<?> clazz) {
        if (clazz == null || !HOOKED_CLASSES.add(clazz.getName())) return;
        for (Method m : clazz.getDeclaredMethods()) {
            String mn = m.getName();
            if (!matchesEvaluateName(mn)) continue;
            Class<?>[] pts = m.getParameterTypes();
            if (pts.length == 0 || pts[0] != String.class) continue;
            try {
                hook(m)
                        .setPriority(XposedInterface.PRIORITY_DEFAULT)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .intercept(chain -> {
                            Object result = chain.proceed();
                            captureEngineAndInject(chain, m);
                            return result;
                        });
                log(Log.INFO, TAG, "[hook] " + clazz.getName() + "." + mn);
            } catch (Throwable t) {
                log(Log.DEBUG, TAG, "[hook] fail " + clazz.getName() + "." + mn + ": " + t.getMessage());
            }
        }
    }

    private boolean matchesEvaluateName(String name) {
        for (String e : EVALUATE_METHODS) {
            if (name.equalsIgnoreCase(e) || name.toLowerCase().contains(e.toLowerCase())) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 捕获引擎实例，延迟注入 payload
    // ------------------------------------------------------------------
    private void captureEngineAndInject(XposedInterface.Chain chain, Method method) {
        try {
            if (INJECTED.get()) return;
            sEngineInstance = chain.getThisObject();
            sEvaluateMethod = method;
            log(Log.INFO, TAG, "engine captured: " + method.getDeclaringClass().getName()
                    + "." + method.getName());
            scheduleInject();
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "captureEngine failed: " + t);
        }
    }

    private void scheduleInject() {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(8000); // 等游戏初始化完成
                injectOnce();
            } catch (Throwable ignored) {
            }
        }, "wxgm-inject");
        t.setDaemon(true);
        t.start();
    }

    private void injectOnce() {
        if (!INJECTED.compareAndSet(false, true)) return;
        Method m = sEvaluateMethod;
        Object engine = sEngineInstance;
        if (m == null || engine == null) {
            log(Log.WARN, TAG, "inject aborted: no engine captured yet");
            return;
        }
        try {
            Class<?>[] pts = m.getParameterTypes();
            Object[] args = new Object[pts.length];
            args[0] = PAYLOAD;
            // 其余参数尽量给默认值（url/scriptName 等）
            for (int i = 1; i < pts.length; i++) {
                Class<?> p = pts[i];
                if (p == String.class) args[i] = "";
                else if (p == boolean.class) args[i] = false;
                else if (p == int.class) args[i] = 0;
                else if (p == long.class) args[i] = 0L;
                else args[i] = null;
            }
            try { m.setAccessible(true); } catch (Throwable ignored) {}
            m.invoke(engine, args);
            log(Log.INFO, TAG, "payload injected via " + m.getName());
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "inject failed: " + t);
        }
    }

    // ------------------------------------------------------------------
    // 注入的 JS：等待 Cocos System 就绪 → hook LayerManager.open → 打开 UITest(4)
    // 与 PC devtools 调试时验证的路径一致：gui.open(4) 即 GM 面板
    // ------------------------------------------------------------------
    private static final String PAYLOAD = """
            (function () {
              var tries = 0;
              function boot() {
                try {
                  var G = (typeof GameGlobal !== 'undefined') ? GameGlobal
                       : (typeof globalThis !== 'undefined' ? globalThis : this);
                  if (!G || !G.System || typeof G.System.import !== 'function') {
                    if (tries++ < 200) { setTimeout(boot, 250); return; }
                  }
                  G.System.import('chunks:///_virtual/LayerManager.ts').then(function (m) {
                    var LM = m && (m.LayerManager || m.default);
                    if (!LM || !LM.prototype || typeof LM.prototype.open !== 'function') {
                      if (tries++ < 200) { setTimeout(boot, 250); return; }
                    }
                    var orig = LM.prototype.open;
                    LM.prototype.open = function (t, e, n) {
                      var r = orig.apply(this, arguments);
                      try { orig.call(this, 4); } catch (err) { /* UIID 4 = UITest (GM) */ }
                      return r;
                    };
                    console.log('[WxGM] LayerManager.open hooked, tap any panel to open GM');
                  }).catch(function () {
                    if (tries++ < 200) { setTimeout(boot, 250); }
                  });
                } catch (e) {
                  if (tries++ < 200) { setTimeout(boot, 250); }
                }
              }
              boot();
            })();
            """;
}
