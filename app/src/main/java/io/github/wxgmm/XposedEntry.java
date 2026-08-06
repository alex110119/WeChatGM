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
            // ★ tinker 补丁 dex 确认：微信小游戏真实 JS 引擎 = J2V8 魔改（mmv8）
            //   （在 tinker 补丁 classloader 里，base.apk 加载不到，靠 loadClass 拦截捕获）
            "com.eclipsesource.mmv8.V8",
            "com.eclipsesource.mmv8.MultiContextV8",
            "com.eclipsesource.mmv8.V8Context",
            "com.eclipsesource.mmv8.V8ContextWrapper",
            // 旧候选（base.apk commonjni，留作对照；实际微信不走这些）
            "com.tencent.mm.appbrand.commonjni.AppBrandCommonBindingJni",
            "com.tencent.cso.CsoLoader",
            "com.tencent.mm.plugin.appbrand.jsruntime.AppBrandJsRuntime",
            "com.tencent.mm.plugin.appbrand.jsruntime.JsRuntime",
            "com.tencent.mm.plugin.appbrand.jsruntime.e",
            "com.tencent.mm.appbrand.v8.V8JsRuntime",
            "com.tencent.mm.plugin.appbrand.jsapi.v8.V8Engine",
    };

    /** 候选 evaluate 方法名（含 J2V8/mmv8 的 execute*Script 系列） */
    private static final String[] EVALUATE_METHODS = {
            "evaluateJavascript", "evaluate", "evaluateJs", "evaluateScript", "eval",
            "executeVoidScript", "executeStringScript", "executeScript",
            "executeIntegerScript", "executeBooleanScript", "executeDoubleScript",
            "executeArrayScript", "executeObjectScript"
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
        log(Log.INFO, TAG, "[STEP-1] module loaded, pid=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[STEP-2] package loaded, first=" + param.isFirstPackage());
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
        log(Log.INFO, TAG, "[STEP-3] package ready, re-hook with final classloader: "
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
            log(Log.INFO, TAG, "[STEP-4] scanDex start, tag=" + tag + " dex=" + dexPaths.size());
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
                            // initialize=false：只加载不初始化，绝不主动触发 clinit
                            // （避免把类标记为 NoClassDefFoundError，破坏微信后续初始化）。
                            Class<?> clazz = Class.forName(name, false, cl);
                            if (clazz != null) {
                                tryHookClassMethods(clazz);
                                // 关键：hookClassInitializer——等微信自己初始化该类后再 hook
                                hookClassInitializerFor(clazz);
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
                            // ★ mmv8 真实引擎类：记录实际加载它的 classloader（tinker 补丁 loader）
                            if (isJsRuntimeClass(name) && HOOKED_CLASSES.add("cls:" + name)) {
                                Object loaderObj = chain.getThisObject();
                                log(Log.INFO, TAG, "[probe] loaded class: " + name
                                        + " loader=" + (loaderObj != null
                                        ? System.identityHashCode(loaderObj) : 0) + " " + loaderObj);
                                if (result instanceof Class) {
                                    Class<?> loaded = (Class<?>) result;
                                    tryHookClassMethods(loaded);
                                    // 关键：注册 clinit 钩子，等微信初始化该类后再重新 hook
                                    hookClassInitializerFor(loaded);
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
        // ★ mmv8（J2V8 魔改）：微信小游戏真实 JS 引擎，tinker 补丁 classloader 加载
        if (lower.contains("eclipsesource") || lower.contains("mmv8")) return true;
        return (lower.contains("appbrand") || lower.contains("jsruntime") || lower.contains("jsbridge"))
                && (lower.contains("v8") || lower.contains("jscore") || lower.contains("javascript")
                || lower.contains("evaluate") || lower.contains("runtime") || lower.contains("js"));
    }

    // ------------------------------------------------------------------
    // 尝试 hook 候选类（false 加载 + 显式激活）
    // ------------------------------------------------------------------
    private void tryHookClass(String className, ClassLoader cl) {
        try {
            // initialize=false：只加载不初始化，绝不主动触发 clinit——
            // CsoLoader 未就绪时主动触发会把类永久标记为 NoClassDefFoundError，
            // 导致微信自己初始化也失败。激活完全交给 hookClassInitializer。
            Class<?> clazz = Class.forName(className, false, cl);
            log(Log.INFO, TAG, "[STEP-5] tryHookClass found: " + className
                    + " loader=" + System.identityHashCode(cl));
            tryHookClassMethods(clazz);      // 预注册 hook（若类已初始化则直接生效）
            hookClassInitializerFor(clazz);  // 关键：等微信自己初始化该类后再重新 hook
        } catch (Throwable t) {
            log(Log.DEBUG, TAG, "[STEP-5] tryHookClass skip " + className + ": " + t.getMessage());
        }
    }

    /** hookClassInitializer：微信自己初始化该类（clinit 完成）后重新 hook 方法 */
    private void hookClassInitializerFor(Class<?> clazz) {
        try {
            hookClassInitializer(clazz)
                    .setPriority(XposedInterface.PRIORITY_DEFAULT)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        // 关键触发日志：拦截器执行 = clinit 真的被微信触发了（区别于仅注册成功）
                        log(Log.INFO, TAG, "[STEP-7] clinit-triggered BEFORE " + clazz.getName()
                                + " loader=" + System.identityHashCode(clazz.getClassLoader()));
                        Object result;
                        try {
                            // clinit 执行：微信自己初始化该类（小游戏打开、CsoLoader 已就绪）
                            result = chain.proceed();
                        } catch (Throwable t) {
                            // 报错日志保留：clinit 失败时打印完整异常（含 cause/msg）
                            log(Log.WARN, TAG, "[clinit-hook] " + clazz.getName()
                                    + " clinit FAILED: " + t
                                    + " | cause=" + (t.getCause() != null ? t.getCause() : "null")
                                    + " | msg=" + t.getMessage());
                            throw t; // 继续抛出，不影响微信自身初始化流程
                        }
                        // clinit 成功：类已初始化、ArtMethod 就绪——移除去重标记并重新 hook
                        log(Log.INFO, TAG, "[STEP-7] clinit-triggered AFTER " + clazz.getName() + " (clinit done)");
                        ClassLoader loader = clazz.getClassLoader();
                        String key = "mtd:" + clazz.getName() + "@"
                                + (loader != null ? System.identityHashCode(loader) : 0);
                        HOOKED_CLASSES.remove(key);
                        tryHookClassMethods(clazz);
                        return result;
                    });
            log(Log.INFO, TAG, "[STEP-6] clinit-hook registered: " + clazz.getName());
        } catch (Throwable t) {
            // ★ ERROR + 完整堆栈：DEBUG 会被 LSPosed 过滤、getMessage() 可能为 null
            //   （如 NoSuchMethodError: <clinit> 不存在/已执行完），导致看不到真实报错
            log(Log.ERROR, TAG, "[clinit-hook] fail " + clazz.getName() + " -> "
                    + t.getClass().getName() + ": " + t.getMessage());
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
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
            boolean isEval = matchesEvaluateName(mn);
            // ★ 过滤条件：只按方法名过滤，不再用 pts[0] != String 硬性要求——
            //   mmv8/J2V8 的 execute*Script 第一个参数可能是 runtime/context 句柄(long)，
            //   脚本字符串在第二位，若按参数类型过滤会把真正的方法全 continue 掉（STEP-8=0 的根因）
            if (!isReady && !isEval) continue;
            try {
                // 官方 example 写法：hook(method).intercept(chain -> ...)，不额外设置 exceptionMode
                hook(m)
                        .intercept(chain -> {
                            // 限流调用日志：每个方法首次被调用时打印，验证 hook 机制是否生效
                            if (CALL_LOG.add(clazz.getName() + "." + mn)) {
                                log(Log.INFO, TAG, "[STEP-9] called: " + clazz.getName() + "." + mn
                                        + (isReady ? " (ready)" : ""));
                            }
                            Object result = chain.proceed();
                            captureEngineAndInject(chain, m, isReady);
                            return result;
                        });
                log(Log.INFO, TAG, "[STEP-8] hook: " + clazz.getName() + "." + mn + (isReady ? " (ready)" : ""));
            } catch (Throwable t) {
                // ★ ERROR + 完整堆栈：DEBUG 会被 LSPosed 过滤、getMessage() 可能为 null，导致看不到真实报错
                log(Log.ERROR, TAG, "[hook] fail " + clazz.getName() + "." + mn + " -> "
                        + t.getClass().getName() + ": " + t.getMessage());
                log(Log.ERROR, TAG, Log.getStackTraceString(t));
            }
        }
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
                log(Log.INFO, TAG, "[STEP-10] engine captured via ready callback: " + method.getName()
                        + " -> " + eval.getName());
                scheduleInject();
            } else {
                // evaluate 方法本身：method 即注入通道
                sEngineInstance = thiz;
                sEvaluateMethod = method;
                log(Log.INFO, TAG, "[STEP-10] engine captured: " + method.getDeclaringClass().getName()
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
            log(Log.WARN, TAG, "[STEP-11] inject retry: no engine captured yet, static=" + isStatic);
            scheduleInject();
            return;
        }
        try {
            Class<?>[] pts = m.getParameterTypes();
            Object[] args = new Object[pts.length];
            // ★ 找到第一个 String 参数位置注入 PAYLOAD——mmv8/J2V8 的 execute*Script
            //   第一个参数可能是 runtime/context 句柄(long)，脚本字符串在第二位
            int scriptIdx = -1;
            for (int i = 0; i < pts.length; i++) {
                if (pts[i] == String.class) { scriptIdx = i; break; }
            }
            if (scriptIdx < 0) {
                log(Log.ERROR, TAG, "[STEP-11] inject abort: no String param in " + m.getName());
                INJECTED.set(false);
                return;
            }
            args[scriptIdx] = PAYLOAD;
            // 其余参数尽量给默认值（url/scriptName/句柄等）
            for (int i = 0; i < pts.length; i++) {
                if (i == scriptIdx) continue;
                Class<?> p = pts[i];
                if (p == String.class) args[i] = "";
                else if (p == boolean.class) args[i] = false;
                else if (p == int.class) args[i] = 0;
                else if (p == long.class) args[i] = 0L;
                else args[i] = null;
            }
            try { m.setAccessible(true); } catch (Throwable ignored) {}
            m.invoke(isStatic ? null : engine, args);
            log(Log.INFO, TAG, "[STEP-11] payload injected via " + m.getName() + " scriptIdx=" + scriptIdx);
        } catch (Throwable t) {
            INJECTED.set(false);
            log(Log.ERROR, TAG, "[STEP-11] inject failed: " + t + " (will retry)");
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
