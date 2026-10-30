pluginManagement {
    val flutterSdkPath =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            val flutterSdkPath = properties.getProperty("flutter.sdk")
            require(flutterSdkPath != null) { "flutter.sdk not set in local.properties" }
            flutterSdkPath
        }

    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    id("com.android.application") version "9.5.0" apply false
    id("org.jetbrains.kotlin.android") version "2.4.0" apply false
}

// Phase 1: resolve android-core from mavenLocal (published via
//   cd rashield-sdk-publish && ./gradlew publishToMavenLocal "-PraspEngineVersion=1.1.0-local"
// before JitPack so a local development build always uses the new engine.
dependencyResolutionManagement {
    @Suppress("UnstableApiUsage")
    repositories {
        mavenLocal()
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

include(":app")

// rasp_shield_native — included here ONLY so this app's existing, proven
// Gradle setup can compile-verify it during SDK development (it is not
// otherwise used by this Flutter app, which talks to android_core via
// :rasp_shield instead — see that plugin's own build.gradle.kts). Both
// :rasp_shield and :rasp_shield_native now resolve android_core through
// mavenLocal (dev) or JitPack (release) — see gradle.properties.
include(":rasp_shield_native")
project(":rasp_shield_native").projectDir =
    File(rootDir, "../../../sdk_rasp/android_native/rasp_shield_native")
