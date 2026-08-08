package io.github.wxgmm;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * WxGM v2：直接 hook 微信高层 JS 执行入口，注入自己的 JS 代码。
 *
 * 推翻 v1（hook mmv8.V8 的 execute*Script，已被证伪——8.0.76 小游戏 JS 不走那些入口）。
 *
 * 已坐实的调用链（本次会话逐一验证）：
 *   - 游戏跑在 appbrand 子进程（LSPosed 自动注入，无需进程判断）
 *   - 微信高层 JS 执行入口 = com.tencent.mm.plugin.appbrand.jsruntime.c0
 *     .evaluateJavascript(String js, ValueCallback cb) : void
 *   - 参数 js 即要执行的 JS 源码 → hook 后替换/追加自己的 JS 即可执行
 *   - 52pojie 参考（旧版微信）：HookBox 注入点 JsValidationInjector（utils.c3.a），
 *     底层调用链同样落在这类 evaluateJavascript/executeScript 高层入口
 *
 * 注入目标（GM 开关）：macro.TEST = !0  （模块导出对象属性，PC 已验证 gui.open 触发）
 */
public class XposedEntry extends XposedModule {

    private static final String TAG = "WxGM";

    /** 目标：微信高层 JS 执行入口（8.0.76 已坐实） */
    private static final String HOOK_CLASS = "com.tencent.mm.plugin.appbrand.jsruntime.c0";
    private static final String HOOK_METHOD = "evaluateJavascript";

    /**
     * 注入的 JS 代码（追加到原 JS 末尾执行）。
     * 先尝试直接改全局 macro（PC DevTools 可访问），失败再走 System.import 模块系统。
     * !0 = true（开启 GM 门禁）
     */
    private static final String PAYLOAD =
            ";try{macro.TEST=!0;console.log('[WxGM] macro.TEST set OK')}catch(e){" +
            "try{System.import('chunks:///_virtual/macro').then(function(m){m.TEST=!0;console.log('[WxGM] macro.TEST via System OK')})}catch(e2){console.log('[WxGM] inject fail '+e2)}}";

    /** 已 hook 的方法 key（含 classloader 身份：不同 loader 的类副本要各自 hook，避免漏掉运行时实际使用的副本） */
    private static final Set<String> HOOKED_KEYS = new HashSet<>();
    /** 限流调用日志：每个方法首次被调用时打印，验证 hook 是否真的触发 */
    private static final Set<String> CALL_LOG = new HashSet<>();

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        log(Log.INFO, TAG, "[v2] module loaded, proc=" + param.getProcessName());
    }

    @Override
    public void onPackageLoaded(PackageLoadedParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        log(Log.INFO, TAG, "[v2] package loaded (first=" + param.isFirstPackage() + ")");
        // onPackageLoaded 阶段 default classloader 可能不是最终副本；
        // 用 onPackageReady 的最终 classloader hook（API 102 推荐时机）。
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!"com.tencent.mm".equals(param.getPackageName())) {
            return;
        }
        ClassLoader cl = param.getClassLoader();
        log(Log.INFO, TAG, "[v2] package ready, hooking " + HOOK_CLASS + "." + HOOK_METHOD
                + " loader=" + System.identityHashCode(cl));
        try {
            hookEvaluateJavascript(cl);
            // 延时再 hook 一轮：appbrand 子进程的类可能是 tinker 补丁 classloader 加载的副本
            scheduleRehook(cl);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "[v2] hook failed: " + t);
            log(Log.ERROR, TAG, Log.getStackTraceString(t));
        }
    }

    /** 核心 hook：找 evaluateJavascript 方法，hook(m).intercept(...) 改 args[0] 注入 JS */
    private void hookEvaluateJavascript(ClassLoader cl) {
        Class<?> clazz = null;
        try {
            clazz = Class.forName(HOOK_CLASS, false, cl);
        } catch (Throwable t) {
            // 当前 classloader 还加载不到（类未初始化/在别的 loader）
            log(Log.WARN, TAG, "[v2] class not found yet: " + HOOK_CLASS + " -> " + t);
            return;
        }
        Method target = null;
        for (Method m : clazz.getDeclaredMethods()) {
            if (HOOK_METHOD.equals(m.getName())) {
                target = m;
                break;
            }
        }
        if (target == null) {
            log(Log.WARN, TAG, "[v2] method not found: " + HOOK_CLASS + "." + HOOK_METHOD);
            return;
        }
        // 按 loader 身份去重（不同 classloader 的类副本是不同对象，各自 hook）
        String key = HOOK_CLASS + "@" + System.identityHashCode(cl) + "." + HOOK_METHOD;
        if (!HOOKED_KEYS.add(key)) {
            log(Log.INFO, TAG, "[v2] already hooked, skip: " + key);
            return;
        }
        log(Log.INFO, TAG, "[v2] found " + target.toGenericString() + " (key=" + key + ")");
        hook(target).intercept(chain -> {
            // 限流：首次被调用时打印，确认 hook 生效
            if (CALL_LOG.add(HOOK_CLASS + "." + HOOK_METHOD)) {
                log(Log.INFO, TAG, "[v2] CALLED: " + HOOK_CLASS + "." + HOOK_METHOD);
            }
            // ★ 官方 API 102：getArgs() 返回不可变 List，无 setArgs；
            //   改参数必须走 proceed(newArgs) 传入新参数数组
            java.util.List<Object> args = chain.getArgs();
            if (args != null && !args.isEmpty() && args.get(0) instanceof String) {
                String orig = (String) args.get(0);
                if (orig != null) {
                    String injected = orig + PAYLOAD;
                    Object[] newArgs = new Object[args.size()];
                    newArgs[0] = injected;
                    for (int i = 1; i < args.size(); i++) {
                        newArgs[i] = args.get(i);
                    }
                    log(Log.INFO, TAG, "[v2] injecting payload (len " + orig.length()
                            + " -> " + injected.length() + ")");
                    return chain.proceed(newArgs);
                }
            }
            return chain.proceed();
        });
        log(Log.INFO, TAG, "[v2] hook installed: " + HOOK_CLASS + "." + HOOK_METHOD);
    }

    private void scheduleRehook(ClassLoader cl) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(4000);
                log(Log.INFO, TAG, "[v2] rehook round, loader=" + System.identityHashCode(cl));
                hookEvaluateJavascript(cl);
            } catch (Throwable ignored) {
            }
        }, "wxgm-rehook");
        t.setDaemon(true);
        t.start();
    }
}
