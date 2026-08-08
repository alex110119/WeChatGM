package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * WxGM v10：hook ClassLoader.loadClass 拦截拿真实 loader，对真实类装 pf.a/e3.c hook。
 *
 * v9 教训（日志实证 185019/185049）：pf.a/e3.c hook 安装成功但 CALLED=0——
 *   param.getClassLoader()（日志 204411092 全进程相同）不是真实 tinker loader，
 *   hook 装在空副本上，方法从未被触发。v2/v7/v9 全部 CALLED=0 的共同根因。
 *
 * v10 方案（官方 API 102 + 日志实证）：
 *   ① hook ClassLoader.loadClass 两个重载（官方 hook(Executable) 支持）
 *      → chain.proceed() 拿真实加载结果，chain.getThisObject() 拿真实 loader
 *      → 当 pf/e3 类被（tinker）loader 加载时，对真实 Class 对象装 hook
 *   ② hook pf.a：p1(jsPath) 含 bundle.js → ThreadLocal 置标志（风险1修复，e3.b 单线程）
 *   ③ hook e3.c()：队尾请求，标志命中时改 scriptText 追加 PAYLOAD（bundle.js 后执行）
 *
 * 官方 API 佐证（github.com/libxposed/api）：
 *   - hook(Executable) → HookBuilder.intercept(Hooker)，Hooker = Object intercept(Chain)
 *   - Chain.getArg(int)/getThisObject()/proceed() 官方存在，无 setResult（改返回值=return）
 *   - log(int, String, String) 官方签名（XposedInterface/XposedInterfaceWrapper）
 *   - ClassLoader.loadClass 非 framework internal，可 hook（HookBuilder 文档仅禁
 *     Constructor#newInstance 与 framework internal）
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";

    /** SourceMapUtil：e3.b 遍历 JS 文件时逐文件调用（p1 = JS 文件名） */
    private static final String SM_CLASS = "com.tencent.mm.plugin.appbrand.pf";
    private static final String SM_METHOD = "a";
    /** 队尾请求工厂：e3.b 批次末尾调用（scriptText 可注入，bundle.js 之后执行） */
    private static final String TAIL_CLASS = "com.tencent.mm.plugin.appbrand.utils.e3";
    private static final String TAIL_METHOD = "c";
    /** 启用条件：JS 文件名含 bundle.js（macro 模块注册所在文件） */
    private static final String TRIGGER = "bundle.js";
    /** p1 参数索引（pf.a(AppBrandRuntime, String p1, String p2)） */
    private static final int PATH_ARG = 1;

    /**
     * 标志：本批 e3.b 命中 bundle.js（e3.c 队尾据此注入）。
     * ★ ThreadLocal：e3.b → pf.a → e3.c 是同一线程同步调用链（MT smali 实证），
     *   ThreadLocal 隔离不同线程/批次的并发，避免全局静态串批次（风险1修复）。
     */
    private static final ThreadLocal<Boolean> FOUND_BUNDLE = new ThreadLocal<>();

    /**
     * 注入的 JS：macro.TEST = !0（GM 门禁开启，!0=true）。
     * e3.c 队尾请求在 bundle.js 之后执行 → macro 已注册 → 直接设置成功。
     */
    private static final String PAYLOAD =
            "\n;(function(){try{macro.TEST=!0;console.log('[WxGM] macro.TEST set OK')}catch(e){" +
            "try{System.import('chunks:///_virtual/macro').then(function(m){if(m){m.TEST=!0;console.log('[WxGM] macro.TEST via System OK')}})}catch(e2){console.log('[WxGM] inject fail '+e2)}}})();";

    private static final Set<String> HOOKED_KEYS = new HashSet<>();
    private static final Set<String> CALL_LOG = new HashSet<>();

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "[v10] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v10] package loaded (first=" + param.isFirstPackage() + ")");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v10] package ready, hooking ClassLoader.loadClass + preloaded try"
                + " loader=" + System.identityHashCode(cl));
        try {
            hookLoadClassInterceptor();
            // ★ 覆盖已预加载的类：onPackageReady 时若 pf/e3 已被微信加载，
            //   loadClass 拦截不会再捕获 → 主动 forName 一次；未加载则等拦截延迟捕获
            tryHookPreloaded(cl);
            scheduleRehook();
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v10] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /**
     * ★ 加载顺序兜底：pf/e3 类若在 onPackageReady 之前已被微信预加载，
     *   loadClass 拦截永远捕获不到（不会再次加载）——这里主动 forName 试 hook；
     *   若类未加载（抛 ClassNotFoundException）则等 loadClass 拦截在加载时捕获。
     *   hookSourceMap/hookTailRequest 内部按 clazz.getClassLoader() 去重，双路径幂等。
     */
    private void tryHookPreloaded(ClassLoader cl) {
        try {
            Class<?> pf = Class.forName(SM_CLASS, false, cl);
            log(Log.INFO, TAG, "[v10] pf 类已预加载 loader="
                    + System.identityHashCode(pf.getClassLoader()));
            hookSourceMap(pf);
        } catch (Throwable t) {
            log(Log.INFO, TAG, "[v10] pf 类未预加载（等 loadClass 拦截）: " + t);
        }
        try {
            Class<?> e3 = Class.forName(TAIL_CLASS, false, cl);
            log(Log.INFO, TAG, "[v10] e3 类已预加载 loader="
                    + System.identityHashCode(e3.getClassLoader()));
            hookTailRequest(e3);
        } catch (Throwable t) {
            log(Log.INFO, TAG, "[v10] e3 类未预加载（等 loadClass 拦截）: " + t);
        }
    }

    /**
     * hook ClassLoader.loadClass 两个重载：拦截 pf/e3 类加载，用真实 loader 的类装 hook。
     * ClassLoader 是系统类，其 loadClass 方法定义全局唯一——hook 一次覆盖所有
     * （含 tinker）loader 的类加载调用，chain.getThisObject() = 实际加载该类的 loader。
     */
    private void hookLoadClassInterceptor() {
        String key = "ClassLoader.loadClass@system";
        if (!HOOKED_KEYS.add(key)) {
            return;
        }
        try {
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class));
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class, boolean.class));
            log(Log.INFO, TAG, "[v10] ClassLoader.loadClass hooked (both overloads)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v10] hookLoadClass failed: " + t);
            HOOKED_KEYS.remove(key);
        }
    }

    private void hookLoadClassOverload(Method loadClass) {
        hook(loadClass).intercept(chain -> {
            Object result = chain.proceed();
            try {
                String name = String.valueOf(chain.getArg(0));
                Object loaderObj = chain.getThisObject();
                // 目标类被真实 loader 加载时，对真实 Class 装 hook
                if (name.equals(SM_CLASS)) {
                    log(Log.INFO, TAG, "[v10] pf 类被加载 loader="
                            + (loaderObj != null ? System.identityHashCode(loaderObj) : 0));
                    if (result instanceof Class) {
                        hookSourceMap((Class<?>) result);
                    }
                } else if (name.equals(TAIL_CLASS)) {
                    log(Log.INFO, TAG, "[v10] e3 类被加载 loader="
                            + (loaderObj != null ? System.identityHashCode(loaderObj) : 0));
                    if (result instanceof Class) {
                        hookTailRequest((Class<?>) result);
                    }
                }
            } catch (Throwable ignored) {
            }
            return result;
        });
    }

    /** ① hook pf.a：p1 含 bundle.js → ThreadLocal 置标志（不改返回值，不污染 sourcemap） */
    private void hookSourceMap(Class<?> clazz) {
        String key = SM_CLASS + "@" + System.identityHashCode(clazz.getClassLoader()) + "." + SM_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v10] pf.a already hooked, skip: " + key);
            return;
        }
        Method target = null;
        for (Method m : clazz.getDeclaredMethods()) {
            // pf.a(AppBrandRuntime, String, String) → String（静态）
            if (SM_METHOD.equals(m.getName())
                    && m.getParameterTypes().length == 3
                    && m.getParameterTypes()[PATH_ARG] == String.class
                    && m.getReturnType() == String.class) {
                target = m;
                break;
            }
        }
        if (target == null) {
            log(Log.WARN, TAG, "[v10] method not found: " + SM_CLASS + "." + SM_METHOD);
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v10] found " + target.toGenericString() + " (key=" + key + ")");
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(SM_CLASS + "." + SM_METHOD)) {
                log(Log.INFO, TAG, "[v10] CALLED: " + SM_CLASS + "." + SM_METHOD
                        + " thread=" + Thread.currentThread().getId());
            }
            // 启用条件判断分支：p1（jsPath）含 bundle.js → 输出是否找到 + ThreadLocal 置标志
            Object pathObj = chain.getArg(PATH_ARG);
            if (pathObj instanceof String && ((String) pathObj).contains(TRIGGER)) {
                log(Log.INFO, TAG, "[v10] bundle.js 已找到 (jsPath=" + pathObj
                        + ") → 开始注入，置标志 FOUND_BUNDLE");
                FOUND_BUNDLE.set(Boolean.TRUE);
            } else {
                log(Log.INFO, TAG, "[v10] jsPath=" + pathObj + " 非 bundle.js（跳过）");
            }
            return chain.proceed();   // 不改返回值，sourcemap 正常走
        });
        log(Log.INFO, TAG, "[v10] hook installed: " + SM_CLASS + "." + SM_METHOD);
    }

    /** ② hook e3.c()：ThreadLocal 标志命中时改 scriptText 追加 PAYLOAD，消费后 remove */
    private void hookTailRequest(Class<?> clazz) {
        String key = TAIL_CLASS + "@" + System.identityHashCode(clazz.getClassLoader()) + "." + TAIL_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v10] e3.c already hooked, skip: " + key);
            return;
        }
        Method target = null;
        for (Method m : clazz.getDeclaredMethods()) {
            if (TAIL_METHOD.equals(m.getName()) && m.getParameterTypes().length == 0) {
                target = m;
                break;
            }
        }
        if (target == null) {
            log(Log.WARN, TAG, "[v10] method not found: " + TAIL_CLASS + "." + TAIL_METHOD + "()");
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v10] found " + target.toGenericString() + " (key=" + key + ")");
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(TAIL_CLASS + "." + TAIL_METHOD)) {
                log(Log.INFO, TAG, "[v10] CALLED: " + TAIL_CLASS + "." + TAIL_METHOD
                        + " thread=" + Thread.currentThread().getId());
            }
            Object result = chain.proceed();
            // 队尾请求：ThreadLocal 标志命中时注入（bundle.js 之后执行 → macro 已注册）
            Boolean found = FOUND_BUNDLE.get();
            if (Boolean.TRUE.equals(found) && result != null) {
                FOUND_BUNDLE.remove();
                try {
                    Field f = findField(result.getClass(), "scriptText");
                    if (f == null) {
                        log(Log.WARN, TAG, "[v10] scriptText field not found on "
                                + result.getClass().getName());
                        return result;
                    }
                    f.setAccessible(true);
                    Object origObj = f.get(result);
                    String orig = origObj == null ? "" : String.valueOf(origObj);
                    String injected = orig + PAYLOAD;
                    f.set(result, injected);
                    log(Log.INFO, TAG, "[v10] 注入完成 (scriptText len "
                            + orig.length() + " -> " + injected.length() + ")");
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "[v10] inject failed: " + t);
                }
            } else {
                log(Log.INFO, TAG, "[v10] e3.c 队尾（FOUND_BUNDLE=" + found
                        + " 或 result=null，跳过）");
            }
            return result;
        });
        log(Log.INFO, TAG, "[v10] hook installed: " + TAIL_CLASS + "." + TAIL_METHOD);
    }

    /** 反射查找字段（含父类） */
    private Field findField(Class<?> clazz, String name) {
        Class<?> c = clazz;
        while (c != null) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
            c = c.getSuperclass();
        }
        return null;
    }

    /** 周期性 rehook：多次尝试（loadClass 拦截是主路径，此处兜底） */
    private void scheduleRehook() {
        Thread t = new Thread(() -> {
            for (int i = 0; i < 10; i++) {
                try {
                    Thread.sleep(3000);
                    log(Log.INFO, TAG, "[v10] rehook round #" + i);
                    // loadClass 拦截已在 onPackageReady 装上，rehook 主要用于
                    // 类加载后确保 hook 已挂（HOOKED_KEYS 防重复，幂等）
                } catch (Throwable ignored) {
                    break;
                }
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
