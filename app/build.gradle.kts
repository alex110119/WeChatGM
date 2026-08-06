plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.wxgmm"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.wxgmm"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            merges += "META-INF/xposed/*"
        }
    }
}

dependencies {
    // LibXposed API 102 —— compileOnly，运行时由 LSPosed 框架提供
    compileOnly("io.github.libxposed:api:102.0.0")
}
