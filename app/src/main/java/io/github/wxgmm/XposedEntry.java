package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * WxGM v9：pf.a 判断 bundle.js 置标志 + e3.c 队尾请求注入 PAYLOAD。
 *
 * v8 教训（用户指正）：hook pf.a 改返回值拿不到 bundle.js 内容——
 *   pf.a 返回的是 sourcemap 代码（非内容），且 v7(sourcemap) 先于 v8(bundle.js) 执行，
 *   PAYLOAD 塞进 sourcemap 请求时 System/macro 均未就绪，无法正确执行。
 *
 * v9 方案（用户确认）：
 *   ① hook pf.a（SourceMapUtil）：p1(jsPath) 含 bundle.js → 置标志 FOUND_BUNDLE + 日志
 *      （只判断+标志，不改返回值，不污染 sourcemap）
 *   ② hook e3.c()（队尾请求工厂）：FOUND_BUNDLE 时改 scriptText 追加 PAYLOAD，复位标志
 *      e3.c 请求在 v7+v8 之后执行 → bundle.js 已执行 → macro 已注册 → PAYLOAD 直接生效
 *
 * MT 静态定位（base.apk 8.0.76）：
 *   e3.b 遍历 paths[]（每个 JS 文件一轮）:
 *     v13 = pf.a(runtime, jsPath, 前缀)   ← p1=jsPath（JS 文件名）
 *     e3.d(jsPath, x3, ...) → Wxa 文件请求（bundle.js 内容）
 *     合并 v7+v8+e3.c() → l0.l0 执行（v7 → v8(bundle.js, macro注册) → e3.c(PAYLOAD)）
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

    /** 标志：本批 e3.b 命中 bundle.js（e3.c 队尾据此注入） */
    private static final java.util.concurrent.atomic.AtomicBoolean FOUND_BUNDLE =
            new java.util.concurrent.atomic.AtomicBoolean(false);

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
        log(Log.INFO, TAG, "[v9] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v9] package loaded (first=" + param.isFirstPackage() + ")");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v9] package ready, hooking " + SM_CLASS + "." + SM_METHOD
                + " + " + TAIL_CLASS + "." + TAIL_METHOD
                + " loader=" + System.identityHashCode(cl));
        try {
            hookSourceMap(cl);
            hookTailRequest(cl);
            scheduleRehook(cl);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v9] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /** ① hook pf.a：p1 含 bundle.js → 置标志 + 日志（不改返回值） */
    private void hookSourceMap(ClassLoader cl) {
        String key = SM_CLASS + "@" + System.identityHashCode(cl) + "." + SM_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            return;
        }
        Class<?> clazz;
        try {
            clazz = Class.forName(SM_CLASS, false, cl);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "[v9] class not found yet: " + SM_CLASS + " -> " + t);
            HOOKED_KEYS.remove(key);
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
            log(Log.WARN, TAG, "[v9] method not found: " + SM_CLASS + "." + SM_METHOD);
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v9] found " + target.toGenericString());
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(SM_CLASS + "." + SM_METHOD)) {
                log(Log.INFO, TAG, "[v9] CALLED: " + SM_CLASS + "." + SM_METHOD);
            }
            // 启用条件判断分支：p1（jsPath）含 bundle.js → 输出是否找到 + 置标志
            Object pathObj = chain.getArg(PATH_ARG);
            if (pathObj instanceof String && ((String) pathObj).contains(TRIGGER)) {
                log(Log.INFO, TAG, "[v9] bundle.js 已找到 (jsPath=" + pathObj
                        + ") → 开始注入，置标志 FOUND_BUNDLE");
                FOUND_BUNDLE.set(true);
            } else {
                log(Log.INFO, TAG, "[v9] jsPath=" + pathObj + " 非 bundle.js（跳过）");
            }
            return chain.proceed();   // 不改返回值，sourcemap 正常走
        });
        log(Log.INFO, TAG, "[v9] hook installed: " + SM_CLASS + "." + SM_METHOD);
    }

    /** ② hook e3.c()：FOUND_BUNDLE 时改 scriptText 追加 PAYLOAD，复位标志 */
    private void hookTailRequest(ClassLoader cl) {
        String key = TAIL_CLASS + "@" + System.identityHashCode(cl) + "." + TAIL_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            return;
        }
        Class<?> clazz;
        try {
            clazz = Class.forName(TAIL_CLASS, false, cl);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "[v9] class not found yet: " + TAIL_CLASS + " -> " + t);
            HOOKED_KEYS.remove(key);
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
            log(Log.WARN, TAG, "[v9] method not found: " + TAIL_CLASS + "." + TAIL_METHOD + "()");
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v9] found " + target.toGenericString());
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(TAIL_CLASS + "." + TAIL_METHOD)) {
                log(Log.INFO, TAG, "[v9] CALLED: " + TAIL_CLASS + "." + TAIL_METHOD);
            }
            Object result = chain.proceed();
            // 队尾请求：FOUND_BUNDLE 时注入（bundle.js 之后执行 → macro 已注册）
            if (FOUND_BUNDLE.getAndSet(false) && result != null) {
                try {
                    Field f = findField(result.getClass(), "scriptText");
                    if (f == null) {
                        log(Log.WARN, TAG, "[v9] scriptText field not found on "
                                + result.getClass().getName());
                        return result;
                    }
                    f.setAccessible(true);
                    Object origObj = f.get(result);
                    String orig = origObj == null ? "" : String.valueOf(origObj);
                    String injected = orig + PAYLOAD;
                    f.set(result, injected);
                    log(Log.INFO, TAG, "[v9] 注入完成 (scriptText len "
                            + orig.length() + " -> " + injected.length() + ")");
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "[v9] inject failed: " + t);
                }
            } else {
                log(Log.INFO, TAG, "[v9] e3.c 队尾（FOUND_BUNDLE=false 或 result=null，跳过）");
            }
            return result;
        });
        log(Log.INFO, TAG, "[v9] hook installed: " + TAIL_CLASS + "." + TAIL_METHOD);
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

    private void scheduleRehook(ClassLoader cl) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(4000);
                log(Log.INFO, TAG, "[v9] rehook round, loader=" + System.identityHashCode(cl));
                hookSourceMap(cl);
                hookTailRequest(cl);
            } catch (Throwable ignored) {
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
