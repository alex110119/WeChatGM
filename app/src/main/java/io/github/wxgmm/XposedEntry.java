package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * WxGM v8：hook pf.a（SourceMapUtil），p1 判断 bundle.js 作为启用条件注入 PAYLOAD。
 *
 * v7 教训（日志实证 + 用户指正）：hook e3.c()（无参队尾工厂）CALLED=0——
 *   无参拿不到 JS 文件名，无法判断"这次加载的是不是 macro 所在文件"。
 *   正确启用条件 = pf.a 的 p1 参数（JS 文件名）：判断是否 bundle.js。
 *
 * MT 静态定位（base.apk 8.0.76，e3.b 内部遍历 paths 时逐文件调用）：
 *   e3.b(f9, t, key, paths[], b3):
 *     遍历 paths[]（每个 JS 文件一轮）:
 *       v13 = pf.a(runtime, jsPath, 前缀)   ← p1=jsPath（JS 文件名）！
 *       if 非空: V8ScriptEvaluateRequest{scriptText=v13, scriptType=3} → v7 队列
 *       e3.d(jsPath, x3, ...) → Wxa 文件请求 → v8 队列
 *     合并 v7+v8+e3.c() → l0.l0(队列) 批量执行
 *
 * pf.a(AppBrandRuntime, String p1=jsPath, String p2) → String（sourcemap 注入代码）
 *   log "hy: getting sourcemap %s, %s" (tag: MicroMsg.SourceMapUtil)
 *
 * 注入方案：
 *   hook pf.a → intercept 里检查 p1（args[1]）是否含 "bundle.js"：
 *     ★ 命中 = 微信即将执行 bundle.js 的时刻（macro 所在文件！）
 *     proceed() 拿原返回值 → return 原值 + PAYLOAD
 *     （★ API 102：Chain 无 setResult，intercept 的返回值即最终结果）
 *   bundle.js 执行 → System.register("chunks:///_virtual/macro") → macro 注册
 *   PAYLOAD 轮询命中 → macro.TEST = !0 成功（无需等注册，轮询天然覆盖）
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";

    /** SourceMapUtil：e3.b 遍历 JS 文件时逐文件调用（p1 = JS 文件名） */
    private static final String HOOK_CLASS = "com.tencent.mm.plugin.appbrand.pf";
    private static final String HOOK_METHOD = "a";
    /** 启用条件：JS 文件名含 bundle.js（macro 模块注册所在文件） */
    private static final String TRIGGER = "bundle.js";
    /** p1 参数索引（pf.a(AppBrandRuntime, String p1, String p2)） */
    private static final int PATH_ARG = 1;

    /**
     * 注入的 JS：轮询等待 macro 注册后设 TEST = !0（GM 门禁开启，!0=true）。
     * 命中 bundle.js 时刻注入 → bundle.js 执行后 macro 注册 → 轮询命中。
     */
    private static final String PAYLOAD =
            "\n;(function(){var n=0,d=false;var t=setInterval(function(){n++;" +
            "if(!d){try{if(typeof macro!=='undefined'&&macro){macro.TEST=!0;d=true;console.log('[WxGM] macro.TEST set OK')}}catch(e){}}" +
            "if(!d){try{System.import('chunks:///_virtual/macro').then(function(m){if(m){m.TEST=!0;d=true;console.log('[WxGM] macro.TEST via System OK')}})}catch(e2){}}" +
            "if(d||n>200){clearInterval(t)}},50)})();";

    private static final Set<String> HOOKED_KEYS = new HashSet<>();
    private static final Set<String> CALL_LOG = new HashSet<>();

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "[v8] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v8] package loaded (first=" + param.isFirstPackage() + ")");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v8] package ready, hooking " + HOOK_CLASS + "." + HOOK_METHOD
                + " loader=" + System.identityHashCode(cl));
        try {
            hookSourceMap(cl);
            scheduleRehook(cl);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v8] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /** hook pf.a：p1 含 bundle.js 时改返回值（追加 PAYLOAD），启用条件 = bundle.js 时刻 */
    private void hookSourceMap(ClassLoader cl) {
        String key = HOOK_CLASS + "@" + System.identityHashCode(cl) + "." + HOOK_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v8] already hooked, skip: " + key);
            return;
        }
        Class<?> clazz;
        try {
            clazz = Class.forName(HOOK_CLASS, false, cl);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "[v8] class not found yet: " + HOOK_CLASS + " -> " + t);
            HOOKED_KEYS.remove(key);
            return;
        }
        Method target = null;
        for (Method m : clazz.getDeclaredMethods()) {
            // pf.a(AppBrandRuntime, String, String) → String（静态）
            if (HOOK_METHOD.equals(m.getName())
                    && m.getParameterTypes().length == 3
                    && m.getParameterTypes()[PATH_ARG] == String.class
                    && m.getReturnType() == String.class) {
                target = m;
                break;
            }
        }
        if (target == null) {
            log(Log.WARN, TAG, "[v8] method not found: " + HOOK_CLASS + "." + HOOK_METHOD
                    + "(AppBrandRuntime, String, String):String");
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v8] found " + target.toGenericString());
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(HOOK_CLASS + "." + HOOK_METHOD)) {
                log(Log.INFO, TAG, "[v8] CALLED: " + HOOK_CLASS + "." + HOOK_METHOD
                        + " (sourcemap 获取触发)");
            }
            // 启用条件：p1（jsPath）含 bundle.js → 微信即将执行 bundle.js（macro 所在文件）
            Object pathObj = chain.getArg(PATH_ARG);
            if (pathObj instanceof String && ((String) pathObj).contains(TRIGGER)) {
                log(Log.INFO, TAG, "[v8] TRIGGERED by jsPath=" + pathObj
                        + " (macro 所在文件，注入 PAYLOAD)");
                // ★ API 102：Chain 无 setResult，intercept 返回值 = 最终返回值
                //   proceed() 拿原返回值（sourcemap 代码），追加 PAYLOAD 后 return
                Object result = chain.proceed();
                String orig = result == null ? "" : String.valueOf(result);
                String injected = orig + PAYLOAD;
                log(Log.INFO, TAG, "[v8] injected payload (ret len "
                        + orig.length() + " -> " + injected.length() + ")");
                return injected;
            }
            return chain.proceed();
        });
        log(Log.INFO, TAG, "[v8] hook installed: " + HOOK_CLASS + "." + HOOK_METHOD);
    }

    private void scheduleRehook(ClassLoader cl) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(4000);
                log(Log.INFO, TAG, "[v8] rehook round, loader=" + System.identityHashCode(cl));
                hookSourceMap(cl);
            } catch (Throwable ignored) {
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
