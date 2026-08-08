package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * WxGM v11：hook V8ContextImpl.batchExecuteScripts（逻辑层 JS 批量执行入口），队尾注入 PAYLOAD。
 *
 * v10 教训（ExecuteDetails 定位 + 用户指正）：pf.a/e3.c 链在日志窗口内从未被加载，
 *   且 pf.a 只是 sourcemap（非内容）。MT 搜 ExecuteDetails 定位到真正的执行入口：
 *   com.eclipsesource.mmv8.V8ContextWrapper$V8ContextImpl
 *     .batchExecuteScripts(ArrayList, String, ExecuteDetails)   ← 逻辑层 JS 批量执行！
 *     该类是 final 具体类（implements V8Context），可 hook。
 *
 * 调用链（MT smali 实证）：
 *   e3.b → l0.l0(ArrayList, String, cl.j1) → cl.h1.run()
 *     → V8Context.batchExecuteScripts(ArrayList<request>, String, ExecuteDetails)
 *     → V8.batchExecuteScripts（native 执行）
 *   ArrayList 内 = V8ScriptEvaluateRequest 列表（含 bundle.js 请求 + e3.c 队尾请求）
 *
 * 注入方案：
 *   hook batchExecuteScripts → intercept 改 args[0]（ArrayList）：
 *     对列表最后一个 request（队尾，bundle.js 之后执行）的 scriptText 追加 PAYLOAD
 *     → bundle.js 执行完 → macro 已注册 → PAYLOAD 轮询命中 → macro.TEST=!0
 *   （保留轮询：框架批次执行时 macro 未注册，轮询兜底）
 *
 * 官方 API 佐证（github.com/libxposed/api）：
 *   - hook(Executable) → HookBuilder.intercept(Hooker)，Hooker = Object intercept(Chain)
 *   - Chain.getArgs()/getArg(int)/proceed() 官方存在，无 setResult（改返回值=return）
 *   - log(int, String, String) 官方签名
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";

    /** 逻辑层 JS 批量执行入口（final 具体类，可 hook；MT 实证） */
    private static final String HOOK_CLASS = "com.eclipsesource.mmv8.V8ContextWrapper$V8ContextImpl";
    private static final String HOOK_METHOD = "batchExecuteScripts";

    /** 启用条件：脚本名含 bundle.js（macro 模块注册所在文件） */
    private static final String TRIGGER = "bundle.js";
    /** 备用判定：scriptText 内容含 macro 模块注册特征 */
    private static final String MACRO_HINT = "_virtual/macro";

    /**
     * 注入的 JS：轮询等待 macro 注册后设 TEST = !0（GM 门禁开启，!0=true）。
     * 队尾 request 在 bundle.js 之后执行 → macro 已注册 → 轮询命中设置成功。
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
        log(Log.INFO, TAG, "[v11] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v11] package loaded (first=" + param.isFirstPackage() + ")");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v11] package ready, hooking " + HOOK_CLASS + "." + HOOK_METHOD
                + " loader=" + System.identityHashCode(cl));
        try {
            hookLoadClassInterceptor();
            // 覆盖已预加载：onPackageReady 主动 forName 试 hook；未加载则等 loadClass 拦截
            tryHookPreloaded(cl);
            scheduleRehook();
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v11] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /** 加载顺序兜底：V8ContextImpl 若已预加载则主动 hook，未加载则等 loadClass 拦截 */
    private void tryHookPreloaded(ClassLoader cl) {
        try {
            Class<?> c = Class.forName(HOOK_CLASS, false, cl);
            log(Log.INFO, TAG, "[v11] 执行类已预加载 loader="
                    + System.identityHashCode(c.getClassLoader()));
            hookBatchExecute(c);
        } catch (Throwable t) {
            log(Log.INFO, TAG, "[v11] 执行类未预加载（等 loadClass 拦截）: " + t);
        }
    }

    /** hook ClassLoader.loadClass 拦截：V8ContextImpl 被真实 loader 加载时对真实类装 hook */
    private void hookLoadClassInterceptor() {
        String key = "ClassLoader.loadClass@system";
        if (!HOOKED_KEYS.add(key)) {
            return;
        }
        try {
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class));
            hookLoadClassOverload(ClassLoader.class.getDeclaredMethod("loadClass", String.class, boolean.class));
            log(Log.INFO, TAG, "[v11] ClassLoader.loadClass hooked (both overloads)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v11] hookLoadClass failed: " + t);
            HOOKED_KEYS.remove(key);
        }
    }

    private void hookLoadClassOverload(Method loadClass) {
        hook(loadClass).intercept(chain -> {
            Object result = chain.proceed();
            try {
                if (HOOK_CLASS.equals(String.valueOf(chain.getArg(0)))) {
                    log(Log.INFO, TAG, "[v11] 执行类被加载 loader="
                            + (chain.getThisObject() != null
                            ? System.identityHashCode(chain.getThisObject()) : 0));
                    if (result instanceof Class) {
                        hookBatchExecute((Class<?>) result);
                    }
                }
            } catch (Throwable ignored) {
            }
            return result;
        });
    }

    /** hook batchExecuteScripts：改 args[0]（ArrayList）队尾 request 的 scriptText 追加 PAYLOAD */
    private void hookBatchExecute(Class<?> clazz) {
        String key = HOOK_CLASS + "@" + System.identityHashCode(clazz.getClassLoader()) + "." + HOOK_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v11] already hooked, skip: " + key);
            return;
        }
        Method target = null;
        for (Method m : clazz.getDeclaredMethods()) {
            // batchExecuteScripts(ArrayList, String, ExecuteDetails) → Object
            if (HOOK_METHOD.equals(m.getName())
                    && m.getParameterTypes().length == 3
                    && m.getParameterTypes()[0] == java.util.ArrayList.class) {
                target = m;
                break;
            }
        }
        if (target == null) {
            log(Log.WARN, TAG, "[v11] method not found: " + HOOK_CLASS + "." + HOOK_METHOD
                    + "(ArrayList, String, ExecuteDetails)");
            HOOKED_KEYS.remove(key);
            return;
        }
        log(Log.INFO, TAG, "[v11] found " + target.toGenericString() + " (key=" + key + ")");
        hook(target).intercept(chain -> {
            if (CALL_LOG.add(HOOK_CLASS + "." + HOOK_METHOD)) {
                log(Log.INFO, TAG, "[v11] CALLED: " + HOOK_CLASS + "." + HOOK_METHOD
                        + " thread=" + Thread.currentThread().getId());
            }
            // 改 args[0]（ArrayList<request>）：先扫描批次是否含 bundle.js，
            // 命中才对队尾 request 的 scriptText 追加 PAYLOAD（bundle.js 之后执行）
            List<Object> args = chain.getArgs();
            if (args != null && args.size() > 0 && args.get(0) instanceof java.util.ArrayList) {
                java.util.ArrayList<?> requests = (java.util.ArrayList<?>) args.get(0);
                int size = requests.size();
                log(Log.INFO, TAG, "[v11] batchExecuteScripts requests.size=" + size);
                // ★ 扫描启用条件：批次里是否有 bundle.js（macro 注册所在文件）
                boolean foundBundle = false;
                if (size > 0) {
                    for (Object req : requests) {
                        try {
                            Field sn = findField(req.getClass(), "scriptName");
                            Field st = findField(req.getClass(), "scriptText");
                            String name = sn != null ? String.valueOf(sn.get(req)) : "";
                            String text = st != null ? String.valueOf(st.get(req)) : "";
                            if ((name != null && name.contains(TRIGGER))
                                    || (text != null && text.contains(MACRO_HINT))) {
                                foundBundle = true;
                                log(Log.INFO, TAG, "[v11] 批次含 bundle.js (scriptName="
                                        + name + ") → 队尾注入");
                                break;
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                }
                if (foundBundle && size > 0) {
                    // 队尾 request = bundle.js 之后执行（e3.c 队尾请求）
                    Object last = requests.get(size - 1);
                    try {
                        Field f = findField(last.getClass(), "scriptText");
                        if (f == null) {
                            log(Log.WARN, TAG, "[v11] scriptText field not found on "
                                    + last.getClass().getName());
                        } else {
                            f.setAccessible(true);
                            Object origObj = f.get(last);
                            String orig = origObj == null ? "" : String.valueOf(origObj);
                            String injected = orig + PAYLOAD;
                            f.set(last, injected);
                            log(Log.INFO, TAG, "[v11] 队尾注入完成 (scriptText len "
                                    + orig.length() + " -> " + injected.length() + ")");
                        }
                    } catch (Throwable t) {
                        log(Log.ERROR, TAG, "[v11] inject failed: " + t);
                    }
                } else {
                    log(Log.INFO, TAG, "[v11] 批次无 bundle.js（跳过，不注入）");
                }
            } else {
                log(Log.WARN, TAG, "[v11] args unexpected: size="
                        + (args == null ? -1 : args.size()));
            }
            return chain.proceed();
        });
        log(Log.INFO, TAG, "[v11] hook installed: " + HOOK_CLASS + "." + HOOK_METHOD);
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

    /** 周期性 rehook 兜底（loadClass 拦截 + forName 是主路径） */
    private void scheduleRehook() {
        Thread t = new Thread(() -> {
            for (int i = 0; i < 10; i++) {
                try {
                    Thread.sleep(3000);
                    log(Log.INFO, TAG, "[v11] rehook round #" + i);
                } catch (Throwable ignored) {
                    break;
                }
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
