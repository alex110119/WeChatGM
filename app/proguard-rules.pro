# 保持入口类与注入逻辑不被混淆（release 构建时）
-keep class io.github.wxgmm.XposedEntry { *; }
-keep class io.github.libxposed.** { *; }
-dontwarn io.github.libxposed.**
