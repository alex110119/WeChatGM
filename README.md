# WeChatGM

微信小游戏 GM 面板注入的 **LibXposed API 102** 模块（LSPosed）。

- 目标：微信 `com.tencent.mm`（8.0.76 测试目标）
- 原理：hook 微信 AppBrand JS 引擎的 evaluate 方法 → 注入 payload → 等待 Cocos `System` 就绪 → hook `LayerManager.prototype.open` → 打开 `UITest`（UIID = 4，即 GM 面板）

## 构建

推送到 GitHub 后由 `.github/workflows/build.yml` 自动编译，产物在 Actions → Build APK → Artifacts（`WeChatGM-debug`）。

本地不构建（无需 Android SDK）。

## 安装

1. 手机安装 **LSPosed**（Zygisk 版，需 root）
2. 安装编译出的 APK，在 LSPosed 管理器中启用模块，勾选作用域 **微信（com.tencent.mm）**
3. 重启微信，打开任意小游戏
4. 观察 LSPosed 日志（tag `WxGM`）：
   - `[probe] loaded class: ...` 会列出微信加载的 JS 运行时相关类名
   - `[hook] ...evaluate...` 表示已 hook 到引擎求值方法
   - `payload injected` 表示注入成功
   - 游戏内打开任意面板（设置/商城等）即会自动触发 GM 面板（`LayerManager.open` 被 hook，调用 `open(4)`）

## 工作机制 / 下一步

微信 Android 版内部类名混淆且随版本变化，本模块第一版以**探测为主**：

- `CANDIDATE_CLASSES` 是一组候选 JS 引擎类名，命中即 hook
- `hookClassLoaderProbe()` 会动态记录所有 appbrand/js/v8 相关类名到日志
- 跑一次后把日志里的 `[probe] loaded class` 贴回来，可进一步把真实类名写进候选列表，实现精确注入

## 注入 payload（对应 PC devtools 验证过的路径）

```js
G.System.import('chunks:///_virtual/LayerManager.ts').then(m => {
  const orig = m.LayerManager.prototype.open;
  m.LayerManager.prototype.open = function (t, e, n) {
    const r = orig.apply(this, arguments);
    try { orig.call(this, 4); } catch (err) {}   // UIID 4 = UITest (GM)
    return r;
  };
});
```

## 免责声明

仅供学习与调试自己的设备使用；修改微信进程存在账号风险，请自行评估。
