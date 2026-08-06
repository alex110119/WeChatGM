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
            // 真机日志确认：微信 8.0.76 实际 JS 求值入口（commonjni）
            "com.tencent.mm.appbrand.commonjni.AppBrandCommonBindingJni",
            // AppBrandCommonBindingJni 静态初始化前置：CsoLoader（Missing initialization 提示）
            // 日志确认真实类名：com.tencent.cso.CsoLoader（不在 commonjni 包！）
            "com.tencent.cso.CsoLoader",
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

    /** 引擎就绪回调（native→Java 必走，用于捕获引擎实例作为注入时机） */
    private static final String[] READY_METHODS = {
            "onJSRuntimeReady", "notifyRuntimeReady", "nativeRuntimeReady",
            "notifyPostRuntimeReady", "notifyCreate", "onWorkerCreated",
            "notifyContextCreated", "notifyBindTo"
    };

    /** 注入一次即可 */
    private static final AtomicBoolean INJECTED = new AtomicBoolean(false);
    /** 记录已 hook 的类，避免重复 */
    private static final Set<String> HOOKED_CLASSES = new HashSet<>();
    /** 限流调用日志：记录已打印过 [called] 的方法，避免刷屏 */
    private static final Set<String> CALL_LOG = new HashSet<>();

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

        // 1) 静态扫描：枚举微信 APK 中 AppBrand/JS 相关类，dump 签名并尝试 hook
        scanAppBrandClasses(param);
        // 2) 探测：hook ClassLoader.loadClass 记录 appbrand/v8/js 相关类名
        hookClassLoaderProbe();
        // 3) 尝试候选类（default classloader 阶段）
        for (String cn : CANDIDATE_CLASSES) {
            tryHookClass(cn, sAppClassLoader);
        }
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        // onPackageLoaded 之后，AppComponentFactory 已实例化 app classloader，
        // 此时 getClassLoader() 返回最终 classloader —— 这是推荐的 hook 时机。
        // 之前用 default classloader 加载的类副本可能不是运行时实际使用的，
        // 导致 hook 静默注册成功但不触发（API 101+ 的坑）。
        ClassLoader finalCl = param.getClassLoader();
        log(Log.INFO, TAG, "WeChat ready, re-hook with final classloader: "
                + System.identityHashCode(finalCl));
        sAppClassLoader = finalCl;
        for (String cn : CANDIDATE_CLASSES) {
            tryHookClass(cn, finalCl);
        }
        // 用最终 classloader 重新跑 DexFile 扫描（覆盖不同 classloader 的副本）
        scanWithClassLoader(param, finalCl);
    }

    // ------------------------------------------------------------------
    // 静态扫描：DexFile 枚举微信 APK 全部类名，过滤 AppBrand/JS 相关类
    // ------------------------------------------------------------------
    private void scanAppBrandClasses(PackageLoadedParam param) {
        try {
            android.content.pm.ApplicationInfo ai = param.getApplicationInfo();
            if (ai == null) {
                log(Log.WARN, TAG, "[scan] no applicationInfo");
                return;
            }
            scanDex(ai.sourceDir, ai.splitSourceDirs, sAppClassLoader, "scan");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[scan] init failed: " + t);
        }
    }

    // onPackageReady：用最终 classloader 再扫一遍（PackageReadyParam 也暴露 ApplicationInfo）
    private void scanWithClassLoader(PackageReadyParam param, ClassLoader cl) {
        try {
            android.content.pm.ApplicationInfo ai = param.getApplicationInfo();
            if (ai == null) {
                log(Log.WARN, TAG, "[scan2] no applicationInfo");
                return;
            }
            scanDex(ai.sourceDir, ai.splitSourceDirs, cl, "scan2");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[scan2] init failed: " + t);
        }
    }

    private void scanDex(String sourceDir, String[] splitDirs, ClassLoader cl, String tag) {
        java.util.List<String> dexPaths = new java.util.ArrayList<>();
        if (sourceDir != null) dexPaths.add(sourceDir);
        if (splitDirs != null) {
            for (String s : splitDirs) {
                if (s != null) dexPaths.add(s);
            }
        }
        log(Log.INFO, TAG, "[" + tag + "] dex count=" + dexPaths.size());
        Thread t = new Thread(() -> {
            int matched = 0;
            for (String dexPath : dexPaths) {
                try {
                    dalvik.system.DexFile dex = new dalvik.system.DexFile(dexPath);
                    java.util.Enumeration<String> entries = dex.entries();
                    while (entries.hasMoreElements()) {
                        String name = entries.nextElement();
                        if (name == null) continue;
                        String lower = name.toLowerCase();
                        if (!(lower.contains("appbrand") || lower.contains("jsruntime")
                                || lower.contains("jsbridge") || lower.contains("jscore")
                                || lower.contains("cso") || lower.contains("csoloader"))) continue;
                        matched++;
                        log(Log.INFO, TAG, "[" + tag + "] class: " + name);
                        if (matched > 300) break;
                        try {
                            // initialize=false：只加载不初始化，避免提前触发 AppBrandCommonBindingJni
                            // 的 clinit（CsoLoader 未就绪会抛 Missing initialization，导致类进入
                            // 初始化失败状态，后续 tryHookClass 的 false 加载也会失败）。
                            // 真正的激活由 hookCsoLoader → activatePending 显式触发。
                            Class<?> clazz = Class.forName(name, false, cl);
                            if (clazz != null) {
                                tryHookClassMethods(clazz);
                                // 与 tryHookClass 一致：false 加载的类必须登记待激活 + 挂 CsoLoader 钩子 + 轮询兜底
                                PENDING_ACTIVATE.add(name);
                                hookCsoLoader(cl);
                                scheduleActivateRetry(name, cl);
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                    dex.close();
                } catch (Throwable ignored) {
                }
            }
            log(Log.INFO, TAG, "[" + tag + "] done, matched=" + matched);
        }, "wxgm-" + tag);
        t.setDaemon(true);
        t.start();
    }

    // ------------------------------------------------------------------
    // 探测：记录微信加载的 JS 运行时相关类名
    // ------------------------------------------------------------------
    private void hookClassLoaderProbe() {
        try {
            // 微信自定义 classloader 可能重写 loadClass(String, boolean)，两个重载都 hook
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class));
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class, boolean.class));
            log(Log.INFO, TAG, "ClassLoader.loadClass hooked for probe (both overloads)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "hookClassLoaderProbe failed: " + t);
        }
    }

    private void hookLoadClassOverload(Method loadClass) {
        try {
            hook(loadClass)
                    .setPriority(XposedInterface.PRIORITY_DEFAULT)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        Object result = chain.proceed();
                        try {
                            String name = String.valueOf(chain.getArg(0));
                            if (isJsRuntimeClass(name) && HOOKED_CLASSES.add("cls:" + name)) {
                                log(Log.INFO, TAG, "[probe] loaded class: " + name);
                                if (result instanceof Class) {
                                    tryHookClassMethods((Class<?>) result);
                                }
                            }
                        } catch (Throwable ignored) {
                        }
                        return result;
                    });
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "hookLoadClassOverload failed: " + t);
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
    // 尝试 hook 候选类（false 加载 + 显式激活）
    // ------------------------------------------------------------------
    private void tryHookClass(String className, ClassLoader cl) {
        try {
            // initialize=false：只加载不初始化（clinit 不执行）。
            // hook 会注册，但 ArtMethod 未初始化，拦截器不触发（伪成功）。
            // 必须显式激活：见 hookCsoLoader + activatePending。
            Class<?> clazz = Class.forName(className, false, cl);
            log(Log.INFO, TAG, "[candidate] found: " + className);
            tryHookClassMethods(clazz);
            PENDING_ACTIVATE.add(className);
            // 事件驱动：hook CsoLoader.initialize 的 after，CsoLoader 就绪即激活
            hookCsoLoader(cl);
            // 轮询兜底：CsoLoader 最终会被微信初始化，轮询触发 clinit
            scheduleActivateRetry(className, cl);
        } catch (Throwable t) {
            log(Log.DEBUG, TAG, "[candidate] skip " + className + ": " + t.getMessage());
        }
    }

    /** 待激活类（false 加载但 clinit 未执行），CsoLoader 就绪后显式激活 */
    private static final Set<String> PENDING_ACTIVATE = new HashSet<>();
    private static volatile boolean CSO_HOOKED = false;

    /** hook CsoLoader 的方法（after 回调）：CsoLoader 初始化时激活待激活类 */
    private void hookCsoLoader(ClassLoader cl) {
        if (CSO_HOOKED) return;
        String[] csoCandidates = {
                // 日志确认真实类名（不在 commonjni 包）
                "com.tencent.cso.CsoLoader",
        };
        for (String cn : csoCandidates) {
            try {
                Class<?> cso = Class.forName(cn, false, cl);
                int hooked = 0;
                for (Method m : cso.getDeclaredMethods()) {
                    // native 方法 Java 层 hook 不到，跳过；
                    // 注意：不限制 static——d(...) 是 nativeInitialize 的 Java 封装（实例方法），
                    // 是 AppBrandCommonBindingJni clinit 要求的 "CsoLoader.initialize" 本体
                    if (java.lang.reflect.Modifier.isNative(m.getModifiers())) continue;
                    try {
                        hook(m).intercept(chain -> {
                            Object result = chain.proceed();
                            activatePending(cl);
                            return result;
                        });
                        hooked++;
                        log(Log.INFO, TAG, "[cso] hooked: " + cn + "." + m.getName());
                    } catch (Throwable ignored) {
                    }
                }
                if (hooked > 0) {
                    CSO_HOOKED = true;
                    log(Log.INFO, TAG, "[cso] CsoLoader hooked, methods=" + hooked);
                    return;
                }
            } catch (Throwable ignored) {
            }
        }
        log(Log.WARN, TAG, "[cso] CsoLoader not found, relying on poll retry");
    }

    /** 显式激活：对待激活类执行 Class.forName(initialize=true) 触发 clinit */
    private void activatePending(ClassLoader cl) {
        for (String cn : new HashSet<>(PENDING_ACTIVATE)) {
            try {
                Class<?> clazz = Class.forName(cn, true, cl); // 触发 clinit
                PENDING_ACTIVATE.remove(cn);
                log(Log.INFO, TAG, "[activate] clinit done: " + cn);
            } catch (Throwable t) {
                log(Log.WARN, TAG, "[activate] fail " + cn + ": " + t.getMessage());
            }
        }
    }

    /** CsoLoader 就绪后轮询激活（最多 60 秒），兜底方案 */
    private void scheduleActivateRetry(String className, ClassLoader cl) {
        Thread t = new Thread(() -> {
            try {
                for (int i = 0; i < 30; i++) {
                    Thread.sleep(2000);
                    try {
                        Class<?> clazz = Class.forName(className, true, cl); // 触发 clinit
                        PENDING_ACTIVATE.remove(className);
                        log(Log.INFO, TAG, "[activate-retry] clinit done after "
                                + ((i + 1) * 2) + "s: " + className);
                        return;
                    } catch (Throwable ignored) {
                        // CsoLoader 还未就绪，继续等
                    }
                }
                log(Log.WARN, TAG, "[activate-retry] give up: " + className);
            } catch (Throwable ignored) {
            }
        }, "wxgm-activate");
        t.setDaemon(true);
        t.start();
    }

    private void tryHookClassMethods(Class<?> clazz) {
        if (clazz == null) return;
        // 去重 key 必须包含 classloader 身份：不同 classloader 的类副本是不同对象，
        // 各自都要 hook，否则会漏掉运行时实际使用的副本
        ClassLoader loader = clazz.getClassLoader();
        String key = "mtd:" + clazz.getName() + "@"
                + (loader != null ? System.identityHashCode(loader) : 0);
        if (!HOOKED_CLASSES.add(key)) return;
        // 诊断：打印 classloader 身份（排查 hook 挂在错误 classloader 副本上的问题）
        try {
            ClassLoader cl = clazz.getClassLoader();
            log(Log.INFO, TAG, "[diag] class " + clazz.getName()
                    + " loader=" + System.identityHashCode(cl) + " " + cl);
            log(Log.INFO, TAG, "[diag] default loader=" + System.identityHashCode(sAppClassLoader)
                    + " " + sAppClassLoader);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[diag] classloader info failed: " + t);
        }
        // dump 所有方法签名，方便定位真实混淆名（含 isNative 标志）
        for (Method m : clazz.getDeclaredMethods()) {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append(m.getName()).append('(');
                Class<?>[] pts = m.getParameterTypes();
                for (int i = 0; i < pts.length; i++) {
                    if (i > 0) sb.append(',');
                    sb.append(pts[i].getSimpleName());
                }
                sb.append(')');
                boolean isNative = java.lang.reflect.Modifier.isNative(m.getModifiers());
                boolean isStatic = java.lang.reflect.Modifier.isStatic(m.getModifiers());
                log(Log.INFO, TAG, "[dump] " + clazz.getName() + "." + sb
                        + (isNative ? " [native]" : "") + (isStatic ? " [static]" : ""));
            } catch (Throwable ignored) {
            }
        }
        for (Method m : clazz.getDeclaredMethods()) {
            String mn = m.getName();
            Class<?>[] pts = m.getParameterTypes();
            boolean isReady = matchesReadyName(mn);
            // 宽松匹配：方法名像 evaluate，或第一个参数是 String（混淆后 evaluate 类方法通常第一个参数是 JS 代码字符串），或引擎就绪回调
            if (pts.length == 0 || (pts[0] != String.class && !isReady)) continue;
            if (!isReady && !matchesEvaluateName(mn) && pts.length > 2) continue;
            try {
                // 官方 example 写法：hook(method).intercept(chain -> ...)，不额外设置 exceptionMode
                hook(m)
                        .intercept(chain -> {
                            // 限流调用日志：每个方法首次被调用时打印，验证 hook 机制是否生效
                            if (CALL_LOG.add(clazz.getName() + "." + mn)) {
                                log(Log.INFO, TAG, "[called] " + clazz.getName() + "." + mn
                                        + (isReady ? " (ready)" : ""));
                            }
                            Object result = chain.proceed();
                            // CsoLoader 的任何方法被调用 → CsoLoader 初始化进行中 → 立即激活待激活类
                            if (isCsoLoaderClass(clazz.getName())) {
                                activatePending(clazz.getClassLoader());
                            }
                            captureEngineAndInject(chain, m, isReady);
                            return result;
                        });
                log(Log.INFO, TAG, "[hook] " + clazz.getName() + "." + mn + (isReady ? " (ready)" : ""));
            } catch (Throwable t) {
                log(Log.DEBUG, TAG, "[hook] fail " + clazz.getName() + "." + mn + ": " + t.getMessage());
            }
        }
    }

    private boolean isCsoLoaderClass(String name) {
        return name != null && name.contains("CsoLoader");
    }

    private boolean matchesReadyName(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        for (String r : READY_METHODS) {
            if (lower.equals(r.toLowerCase())) return true;
        }
        return false;
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
    private void captureEngineAndInject(XposedInterface.Chain chain, Method method, boolean isReady) {
        try {
            if (INJECTED.get()) return;
            Object thiz = chain.getThisObject();
            // 静态方法拿不到实例（thiz == null），改用 declaringClass 找注入通道
            Class<?> owner = thiz != null ? thiz.getClass() : method.getDeclaringClass();
            if (isReady) {
                // 就绪回调：引擎已创建，从声明类中找 evaluateScript 作为注入通道
                Method eval = findEvaluateMethod(owner);
                if (eval == null) {
                    log(Log.WARN, TAG, "ready callback but no evaluate method in " + owner.getName());
                    return;
                }
                sEngineInstance = thiz; // static 回调时为 null，injectOnce 会走静态注入
                sEvaluateMethod = eval;
                log(Log.INFO, TAG, "engine captured via ready callback: " + method.getName()
                        + " -> " + eval.getName());
                scheduleInject();
            } else {
                // evaluate 方法本身：method 即注入通道
                sEngineInstance = thiz;
                sEvaluateMethod = method;
                log(Log.INFO, TAG, "engine captured: " + method.getDeclaringClass().getName()
                        + "." + method.getName());
                scheduleInject();
            }
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "captureEngine failed: " + t);
        }
    }

    private Method findEvaluateMethod(Class<?> clazz) {
        for (String e : EVALUATE_METHODS) {
            try {
                for (Method m : clazz.getDeclaredMethods()) {
                    if (m.getName().equalsIgnoreCase(e) || m.getName().toLowerCase().contains(e.toLowerCase())) {
                        Class<?>[] pts = m.getParameterTypes();
                        if (pts.length >= 1 && pts[0] == String.class) {
                            return m;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return null;
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
        boolean isStatic = m != null && java.lang.reflect.Modifier.isStatic(m.getModifiers());
        if (m == null || (!isStatic && engine == null)) {
            // 还没捕获到引擎实例：重置标志，稍后重试（最多 3 次）
            INJECTED.set(false);
            log(Log.WARN, TAG, "inject retry: no engine captured yet, static=" + isStatic);
            scheduleInject();
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
            m.invoke(isStatic ? null : engine, args);
            log(Log.INFO, TAG, "payload injected via " + m.getName());
        } catch (Throwable t) {
            INJECTED.set(false);
            log(Log.ERROR, TAG, "inject failed: " + t + " (will retry)");
            scheduleInject();
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
