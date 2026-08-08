# WeChatGM

微信小游戏 GM 面板注入的 **LibXposed API 102** 模块（LSPosed）。

- 目标：微信 `com.tencent.mm`（8.0.76 测试目标）
- 原理：hook 微信高层 JS 执行入口 `com.tencent.mm.plugin.appbrand.jsruntime.c0.evaluateJavascript(String, ValueCallback)` → 追加注入 JS → 设置 `macro.TEST = !0`（GM 门禁开启）→ 配合游戏内金币连点 ×3 触发 GM 面板（`gui.open(4)` / UITest，PC 已验证）

## 注入点（8.0.76 已坐实）

```
com.tencent.mm.plugin.appbrand.jsruntime.c0.evaluateJavascript(String js, ValueCallback cb)
```

- 游戏跑在 appbrand 子进程，LSPosed 自动注入，模块无需进程判断
- hook 后把原 JS 追加 PAYLOAD 再 `chain.proceed(newArgs)` 执行
- PAYLOAD：先试全局 `macro.TEST=!0`，失败走 `System.import('chunks:///_virtual/macro').then(m=>m.TEST=!0)` 兜底
- `!1`=false=关闭，`!0`=true=开启（PC DevTools 验证过 `gui.open` 触发链）

## 构建

推送到 GitHub 后由 `.github/workflows/build.yml` 自动编译，产物在 Actions → Build APK → Artifacts（`WeChatGM-debug`）。本地也可 `gradle assembleDebug`（需 Android SDK + JDK 17）。

## 安装

1. 手机安装 **LSPosed**（Zygisk 版，需 root）
2. 安装编译出的 APK，在 LSPosed 管理器中启用模块，勾选作用域 **微信（com.tencent.mm）**
3. 重启微信，打开小游戏
4. 观察 LSPosed 日志（tag `WxGM`）逐级确认：
   - `[v2] module loaded` / `[v2] package ready` → 模块注入成功
   - `[v2] hook installed: ...c0.evaluateJavascript` → hook 装上
   - `[v2] CALLED: ...c0.evaluateJavascript` → hook 被触发
   - `[v2] injecting payload (len X -> Y)` → 注入执行
   - JS 侧 `[WxGM] macro.TEST set OK` / `via System OK` → 标志位设置成功
5. 游戏内金币连点 ×3 → GM 面板（UITest）弹出

## 免责声明

仅供学习与调试自己的设备使用；修改微信进程存在账号风险，请自行评估。
