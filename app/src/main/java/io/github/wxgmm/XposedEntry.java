package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * WxGM v7：hook e3.c()（JsValidationInjector 队列末尾字符串请求），bundle.js 之后注入。
 *
 * v6 教训（xref 实证）：e3.h 只在无 v8 路径被 service.f.h 调用；8.0.76 有 libmmv8
 *   → evaluateScriptFile 走 k()（有 v8）→ e3.b → 队尾 e3.c()。v6 hook e3.h 偏离实际路径。
 *
 * MT 静态定位（base.apk 8.0.76）：
 *   service.f.evaluateScriptFile(int, String):
 *     t.h0(l0.class) → u
 *     ├─ u == null → log "without v8" → f()读内容 → service.f.h(...)  [无v8路径]
 *     └─ u != null → service.f.k(...) → e3.b(f9,t,key,paths[],b3)     [有v8路径★]
 *          ├─ v7 = pf.a(...) sourcemap（scriptType=3）
 *          ├─ v8 = e3.d(...) Wxa 文件（scriptType=2，含 bundle.js）
 *          ├─ e3.c() → V8ScriptEvaluateRequest{scriptType=3,
 *          │     scriptText="\n;(function(){return 0x2b67;})();"}   ← 队列末尾!★hook点
 *          └─ l0.l0(队列) 批量执行（e3.c 请求最后执行 → bundle.js 之后 → macro 已注册）
 *
 * 注入方案：hook e3.c() 返回值，scriptText 追加 PAYLOAD（多轮注入 + 轮询等待 macro）。
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";

    /** JsValidationInjector 队列末尾请求工厂（MT 实证，静态无参方法） */
    private static final String INJECT_CLASS = "com.tencent.mm.plugin.appbrand.utils.e3";
    private static final String INJECT_METHOD = "c";

    /**
     * 注入的 JS：轮询等待 macro 注册后设 TEST = !0（GM 门禁开启，!0=true）。
     * e3.c() 每轮 JS 加载批次都会调用（含框架 JS），不能假设该轮 macro 已注册——
     * setInterval 每 50ms 检查，macro 可用或 System.import 成功即设值（最多 10 秒）。
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
        log(Log.INFO, TAG, "[v7] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v7] package loaded (first=" + param.isFirstPackage() + ")");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v7] package ready, hooking " + INJECT_CLASS + "." + INJECT_METHOD
                + " loader=" + System.identityHashCode(cl));
        try {
            hookTailRequest(cl);
            scheduleRehook(cl);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v7] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /** hook e3.c()：after 改返回值 scriptText，追加 PAYLOAD（多轮注入，队列末尾=bundle.js 之后） */
    private void hookTailRequest(ClassLoader cl) {
        String key = INJECT_CLASS + "@" + System.identityHashCode(cl) + "." + INJECT_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v7] already hooked, skip: " + key);
            return;
        }
        Class<?> clazz;
        try {
            clazz = Class.forName(INJECT_CLASS, false, cl);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "[v7] class not found yet: " + INJECT_CLASS + " -> " + t);
            HOOKED_KEYS.remove(key);
            return;
        }
        Method target = null;
        for (Method m : clazz.getDeclaredMethods()) {
            if (INJECT_METHOD.equals(m.getName()) && m.getParameterTypes().length == 0) {
                target = m;
                break;
            }
        }
        if (target == null) {
            log(Log.WARN, TAG, "[v7] method not found: " + INJECT_CLASS + "." + INJECT_METHOD + "()");
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v7] found " + target.toGenericString());
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(INJECT_CLASS + "." + INJECT_METHOD)) {
                log(Log.INFO, TAG, "[v7] CALLED: " + INJECT_CLASS + "." + INJECT_METHOD
                        + " (队列末尾请求工厂触发)");
            }
            Object result = chain.proceed();
            // after：改返回值 scriptText = 原值 + PAYLOAD。
            // ★ 多轮注入：e3.c() 每轮 JS 加载批次（框架加载、小游戏加载...）都会调用，
            //   每轮都注入——框架加载那轮轮询可能超时（macro 未注册），小游戏那轮必成功。
            if (result != null) {
                try {
                    Field f = findField(result.getClass(), "scriptText");
                    if (f == null) {
                        log(Log.WARN, TAG, "[v7] scriptText field not found on "
                                + result.getClass().getName());
                        return result;
                    }
                    f.setAccessible(true);
                    Object origObj = f.get(result);
                    String orig = origObj == null ? "" : String.valueOf(origObj);
                    String injected = orig + PAYLOAD;
                    f.set(result, injected);
                    log(Log.INFO, TAG, "[v7] injected payload (scriptText len "
                            + orig.length() + " -> " + injected.length() + ")");
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "[v7] inject failed: " + t);
                }
            }
            return result;
        });
        log(Log.INFO, TAG, "[v7] hook installed: " + INJECT_CLASS + "." + INJECT_METHOD);
    }

    /** 反射查找 scriptText 字段（含父类） */
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
                log(Log.INFO, TAG, "[v7] rehook round, loader=" + System.identityHashCode(cl));
                hookTailRequest(cl);
            } catch (Throwable ignored) {
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
