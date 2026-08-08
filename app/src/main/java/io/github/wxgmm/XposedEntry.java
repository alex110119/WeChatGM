package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * WxGM v4：hook JsValidationInjector 队列末尾请求（e3.c），在 bundle.js 之后注入 payload。
 *
 * v3 教训（用户指出 + MT 实证）：hook h()/evaluateScriptFile 时机仍不对——
 *   h() 是无 v8 路径（8.0.76 有 v8 走 k()→e3.b）；且必须保证 bundle.js 先执行
 *   （macro 在 bundle.js 注册，bundle.js 不执行则 macro 不存在，System.import 失败）。
 *
 * MT 静态定位（base.apk 8.0.76，JsValidationInjector = e3.b，日志 tag
 *   MicroMsg.JsValidationInjectorWC）：
 *   e3.b(f9, t, key, paths[], b3) 批量注入用户 JS 文件:
 *     ├─ v7 = pf.a(...) sourcemap 请求（scriptType=3）
 *     ├─ v8 = e3.d(...) Wxa 文件请求（scriptType=2，含 bundle.js 内容）
 *     ├─ e3.c() → V8ScriptEvaluateRequest{scriptType=3,
 *     │     scriptText="\n;(function(){return 0x2b67;})();"}   ← 队列末尾!
 *     └─ l0.l0(v0) 批量执行（e3.c 请求最后执行 → bundle.js 之后 → macro 已注册）
 *
 * 注入方案：hook e3.c() 返回值，在 scriptText 后追加 PAYLOAD。
 *   bundle.js 执行完（macro 注册）→ 最后执行我们的 PAYLOAD → macro.TEST = !0 成功。
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";

    /** JsValidationInjector 队列末尾请求工厂（MT 实证，静态无参方法） */
    private static final String INJECT_CLASS = "com.tencent.mm.plugin.appbrand.utils.e3";
    private static final String INJECT_METHOD = "c";
    /** 返回类型：V8ScriptEvaluateRequest（scriptText 字段可注入） */
    private static final String REQ_CLASS = "com.eclipsesource.mmv8.V8ScriptEvaluateRequest";

    /** 注入的 JS：macro.TEST = !0（GM 门禁开启，!0=true；bundle.js 后执行，macro 已注册） */
    private static final String PAYLOAD =
            "\n;(function(){try{macro.TEST=!0;console.log('[WxGM] macro.TEST set OK')}catch(e){" +
            "try{System.import('chunks:///_virtual/macro').then(function(m){m.TEST=!0;console.log('[WxGM] macro.TEST via System OK')})}catch(e2){console.log('[WxGM] inject fail '+e2)}}})();";

    private static final Set<String> HOOKED_KEYS = new HashSet<>();
    private static final Set<String> CALL_LOG = new HashSet<>();
    private static final java.util.concurrent.atomic.AtomicBoolean INJECTED =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "[v4] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v4] package loaded (first=" + param.isFirstPackage() + ")");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v4] package ready, hooking " + INJECT_CLASS + "." + INJECT_METHOD
                + " loader=" + System.identityHashCode(cl));
        try {
            hookTailRequest(cl);
            scheduleRehook(cl);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v4] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /** hook e3.c()：after 改返回值 scriptText，追加 PAYLOAD（队列末尾 = bundle.js 之后） */
    private void hookTailRequest(ClassLoader cl) {
        String key = INJECT_CLASS + "@" + System.identityHashCode(cl) + "." + INJECT_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v4] already hooked, skip: " + key);
            return;
        }
        Class<?> clazz;
        try {
            clazz = Class.forName(INJECT_CLASS, false, cl);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "[v4] class not found yet: " + INJECT_CLASS + " -> " + t);
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
            log(Log.WARN, TAG, "[v4] method not found: " + INJECT_CLASS + "." + INJECT_METHOD + "()");
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v4] found " + target.toGenericString());
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(INJECT_CLASS + "." + INJECT_METHOD)) {
                log(Log.INFO, TAG, "[v4] CALLED: " + INJECT_CLASS + "." + INJECT_METHOD
                        + " (队列末尾请求工厂触发)");
            }
            Object result = chain.proceed();
            // after：改返回值 scriptText = 原值 + PAYLOAD
            if (!INJECTED.get() && result != null) {
                try {
                    Field f = findField(result.getClass(), "scriptText");
                    if (f == null) {
                        log(Log.WARN, TAG, "[v4] scriptText field not found on "
                                + result.getClass().getName());
                        return result;
                    }
                    f.setAccessible(true);
                    Object origObj = f.get(result);
                    String orig = origObj == null ? "" : String.valueOf(origObj);
                    String injected = orig + PAYLOAD;
                    f.set(result, injected);
                    log(Log.INFO, TAG, "[v4] injected payload (scriptText len "
                            + orig.length() + " -> " + injected.length() + ")");
                    INJECTED.set(true);
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "[v4] inject failed: " + t);
                }
            }
            return result;
        });
        log(Log.INFO, TAG, "[v4] hook installed: " + INJECT_CLASS + "." + INJECT_METHOD);
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
                log(Log.INFO, TAG, "[v4] rehook round, loader=" + System.identityHashCode(cl));
                hookTailRequest(cl);
            } catch (Throwable ignored) {
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
