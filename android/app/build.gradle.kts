plugins {
    id("com.android.application")
}

android {
    namespace = "io.pipe.app"
    compileSdk = 36
    buildToolsVersion = "36.1.0"
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "io.pipe.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 14
        versionName = "0.7.3-alpha"
    }
    buildFeatures {
        buildConfig = true
    }
    signingConfigs {
        getByName("debug") {
            storeFile = gradle.gradleUserHomeDir.resolve("pipe-debug.keystore")
        }
        providers.environmentVariable("PIPE_ANDROID_RELEASE_STORE").orNull?.let { path ->
            create("release") {
                storeFile = file(path)
                storePassword = file(providers.environmentVariable("PIPE_ANDROID_RELEASE_PASSWORD_FILE").get())
                    .readText().trimEnd('\r', '\n')
                keyAlias = providers.environmentVariable("PIPE_ANDROID_RELEASE_ALIAS").getOrElse("pipe")
                keyPassword = storePassword
            }
        }
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.findByName("release")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = false
        }
    }
    // The Go shared library compresses well. Keep that saving in the APK.
    packaging.jniLibs.useLegacyPackaging = true
}

dependencies {
    debugImplementation(files("libs/pipe-debug.aar"))
    releaseImplementation(files("libs/pipe.aar"))
}
