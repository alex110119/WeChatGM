package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * WxGM v14：hook jsruntime.n.evaluateJavascript + deoptimize，PAYLOAD 轮询注入 macro.TEST=!0。
 *
 * v13 修正（日志实证 220140/220157）：method not found: jsruntime.q.evaluateJavascript——
 *   jsruntime.q 继承 jsruntime.n 未 override，getDeclaredMethods 找不到（只返回本类声明）。
 *   → ★ hook 声明处 jsruntime.n（MT smali 实证其 evaluateJavascript 是具体方法，可 hook）
 *
 * 定位结论（MT 静态 + 运行时实证）：
 *   - 小游戏跑在 appbrand 进程，逻辑层 JS 经 V8（libmmv8）执行
 *   - 微信注入链：na1/x.k → service.f.k → e3.b → batchExecuteScripts → V8
 *   - na1/x.k 内部 invoke-virtual jsruntime.n.evaluateJavascript(String, ValueCallback)
 *   - jsruntime.n.evaluateJavascript 内部: n0()→cl.q0（引擎）→ cl.q0.d(JS内容, cl.j1) 执行
 *   - bundle.js（macro 注册）经 Cocos System 模块系统 JS 侧加载
 *
 * v12 教训（日志实证 + 用户锁定的 B）：此前 CALLED=0 因短方法被内联
 *   （官方文档："short hooked method B invoked by A, callback not invoked after
 *   hooking, which may mean A has inlined B — deoptimize A and hook takes effect"）
 *   → ★ deoptimize 是生效条件，必须调用
 *
 * 注入方案：
 *   ① hook jsruntime.n.evaluateJavascript(String, ValueCallback)（具体方法，声明处）
 *      args[0]（JS 内容）含 "_virtual/macro" 或 "bundle.js"（macro 注册特征）→ 追加 PAYLOAD
 *   ② ★ deoptimize(target)（官方 XposedInterface 方法，防内联）
 *   ③ PAYLOAD 轮询等 macro 注册 → macro.TEST=!0（GM 门禁开启）
 *   ④ 三路径覆盖：forName（预加载）+ loadClass 拦截（延迟）+ rehook（兜底）
 *
 * 官方 API 佐证（github.com/libxposed/api）：
 *   - hook(Executable) → HookBuilder.intercept(Hooker)，Hooker = Object intercept(Chain)
 *   - Chain.getArgs()/getArg(int)/proceed(Object[]) 官方存在，无 setResult/setArg
 *     （改参数=proceed(newArgs)，改返回值=return）
 *   - deoptimize(Executable) 官方存在（XposedInterface/XposedInterfaceWrapper）
 *   - log(int, String, String) 官方签名
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";

    /**
     * 逻辑层 JS 执行实现类（MT 实证）：
     *   jsruntime.n.evaluateJavascript(String, ValueCallback) 是【具体方法】（非抽象，可 hook）
     *   内部: n0() → cl.q0（引擎）→ cl.q0.d(JS内容, cl.j1回调) 执行
     *   jsruntime.q 继承 n 未 override → getDeclaredMethods 找不到（v13 method not found 根因）
     *   ★ hook 声明处 jsruntime.n（子类实例调用时同样走 n 的实现）
     */
    private static final String HOOK_CLASS = "com.tencent.mm.plugin.appbrand.jsruntime.n";
    private static final String HOOK_METHOD = "evaluateJavascript";
    /** 注入判定特征：JS 内容含 macro 模块注册（chunks:///_virtual/macro）或 bundle.js */
    private static final String MACRO_HINT = "_virtual/macro";
    private static final String BUNDLE_HINT = "bundle.js";

    /**
     * 注入的 JS：轮询等待 macro 注册后设 TEST = !0（GM 门禁开启，!0=true）。
     * game.js 执行 → System.import 链 → bundle.js → macro 注册 → 轮询命中设置成功。
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
        log(Log.INFO, TAG, "[v13] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v13] package loaded (first=" + param.isFirstPackage() + ")");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v13] package ready, hooking " + HOOK_CLASS + "." + HOOK_METHOD
                + " loader=" + System.identityHashCode(cl));
        try {
            hookLoadClassInterceptor();
            tryHookPreloaded(cl);
            scheduleRehook();
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v13] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /** 加载顺序兜底：jsruntime.q 若已预加载则主动 hook，未加载则等 loadClass 拦截 */
    private void tryHookPreloaded(ClassLoader cl) {
        try {
            Class<?> c = Class.forName(HOOK_CLASS, false, cl);
            log(Log.INFO, TAG, "[v13] 执行类已预加载 loader="
                    + System.identityHashCode(c.getClassLoader()));
            hookEvaluateJavascript(c);
        } catch (Throwable t) {
            log(Log.INFO, TAG, "[v13] 执行类未预加载（等 loadClass 拦截）: " + t);
        }
    }

    /** hook ClassLoader.loadClass 拦截：jsruntime.q 被真实 loader 加载时对真实类装 hook */
    private void hookLoadClassInterceptor() {
        String key = "ClassLoader.loadClass@system";
        if (!HOOKED_KEYS.add(key)) {
            return;
        }
        try {
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class));
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class, boolean.class));
            log(Log.INFO, TAG, "[v13] ClassLoader.loadClass hooked (both overloads)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v13] hookLoadClass failed: " + t);
            HOOKED_KEYS.remove(key);
        }
    }

    private void hookLoadClassOverload(Method loadClass) {
        hook(loadClass).intercept(chain -> {
            Object result = chain.proceed();
            try {
                if (HOOK_CLASS.equals(String.valueOf(chain.getArg(0)))) {
                    log(Log.INFO, TAG, "[v13] 执行类被加载 loader="
                            + (chain.getThisObject() != null
                            ? System.identityHashCode(chain.getThisObject()) : 0));
                    if (result instanceof Class) {
                        hookEvaluateJavascript((Class<?>) result);
                    }
                }
            } catch (Throwable ignored) {
            }
            return result;
        });
    }

    /** hook jsruntime.q.evaluateJavascript(String, ValueCallback)：args[0] 含 macro 特征则注入 PAYLOAD */
    private void hookEvaluateJavascript(Class<?> clazz) {
        String key = HOOK_CLASS + "@" + System.identityHashCode(clazz.getClassLoader()) + "." + HOOK_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v13] already hooked, skip: " + key);
            return;
        }
        Method target = null;
        for (Method m : clazz.getDeclaredMethods()) {
            if (HOOK_METHOD.equals(m.getName())
                    && m.getParameterTypes().length == 2
                    && m.getParameterTypes()[0] == String.class) {
                target = m;
                break;
            }
        }
        if (target == null) {
            log(Log.WARN, TAG, "[v13] method not found: " + HOOK_CLASS + "." + HOOK_METHOD
                    + "(String, ValueCallback)");
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v13] found " + target.toGenericString() + " (key=" + key + ")");
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(HOOK_CLASS + "." + HOOK_METHOD)) {
                log(Log.INFO, TAG, "[v13] CALLED: " + HOOK_CLASS + "." + HOOK_METHOD
                        + " thread=" + Thread.currentThread().getId());
            }
            // args[0] = JS 内容；含 macro 注册特征（_virtual/macro 或 bundle.js）则注入 PAYLOAD
            List<Object> args = chain.getArgs();
            if (args != null && args.size() > 0 && args.get(0) instanceof String) {
                String js = (String) args.get(0);
                if (js != null && (js.contains(MACRO_HINT) || js.contains(BUNDLE_HINT))) {
                    String injected = js + PAYLOAD;
                    Object[] newArgs = new Object[args.size()];
                    for (int i = 0; i < args.size(); i++) {
                        newArgs[i] = args.get(i);
                    }
                    newArgs[0] = injected;
                    log(Log.INFO, TAG, "[v13] 命中 macro 特征，注入 (len "
                            + js.length() + " -> " + injected.length() + ")");
                    return chain.proceed(newArgs);
                }
            }
            return chain.proceed();
        });
        // ★ 生效条件：短方法被内联时 hook 不触发，deoptimize 强制不内联（官方 API）
        try {
            boolean ok = deoptimize(target);
            log(Log.INFO, TAG, "[v13] deoptimize(" + HOOK_METHOD + ") = " + ok);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v13] deoptimize failed: " + t);
        }
        log(Log.INFO, TAG, "[v13] hook installed: " + HOOK_CLASS + "." + HOOK_METHOD);
    }

    /** 周期性 rehook 兜底（loadClass 拦截 + forName 是主路径） */
    private void scheduleRehook() {
        Thread t = new Thread(() -> {
            for (int i = 0; i < 10; i++) {
                try {
                    Thread.sleep(3000);
                    log(Log.INFO, TAG, "[v13] rehook round #" + i);
                } catch (Throwable ignored) {
                    break;
                }
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
