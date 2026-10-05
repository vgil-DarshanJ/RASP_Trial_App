import java.security.KeyStore
import java.security.MessageDigest
import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.example.rasp_trial"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.example.rasp_trial"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    // Release signing (Task 6.0): android/key.properties when present
    // (storeFile, storePassword, keyAlias, keyPassword — never committed, see
    // .gitignore); otherwise the debug keys, so `flutter run --release` works.
    val keyProperties = rootProject.file("key.properties")
    if (keyProperties.exists()) {
        val props = Properties().apply { keyProperties.inputStream().use { load(it) } }
        signingConfigs.create("release") {
            storeFile = rootProject.file(props.getProperty("storeFile"))
            storePassword = props.getProperty("storePassword")
            keyAlias = props.getProperty("keyAlias")
            keyPassword = props.getProperty("keyPassword")
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }
}

// ── RASP build config (Task 6.0 Part 2.1) ───────────────────────────────────
// Before the Dart code is compiled, writes the SHA-256 of the certificate this
// variant is signed with to ../assets/generated/rasp_build.json (a Flutter
// asset, gitignored). The app passes it to the SDK as
// expectedSigningCertSha256, so `tamper` can tell a re-signed APK. Only the
// public certificate hash is written; passwords stay in memory.
fun signingCertSha256(storeFile: File?, storePassword: String?, keyAlias: String?): String? {
    if (storeFile == null || !storeFile.exists() || keyAlias == null) return null
    for (type in listOf("PKCS12", "JKS")) {
        try {
            val ks = KeyStore.getInstance(type)
            storeFile.inputStream().use { ks.load(it, storePassword?.toCharArray()) }
            val cert = ks.getCertificate(keyAlias) ?: continue
            return MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02X".format(it) }
        } catch (e: Exception) {
            // try the next keystore type
        }
    }
    return null
}

val raspBuildConfigFile = rootProject.file("../assets/generated/rasp_build.json")
listOf("Debug", "Profile", "Release").forEach { variant ->
    val buildType = variant.lowercase()
    val generate = tasks.register("generateRaspBuildConfig$variant") {
        val signing = android.buildTypes.getByName(buildType).signingConfig
            ?: android.signingConfigs.getByName("debug")
        val storeFile = signing.storeFile
        val storePassword = signing.storePassword
        val keyAlias = signing.keyAlias
        val signingName = signing.name
        outputs.upToDateWhen { false }
        doLast {
            val hash = signingCertSha256(storeFile, storePassword, keyAlias)
            val hashJson = if (hash == null) "null" else "\"" + hash + "\""
            raspBuildConfigFile.parentFile.mkdirs()
            raspBuildConfigFile.writeText(
                "{\"variant\":\"" + buildType + "\",\"signingConfig\":\"" + signingName + "\"," +
                    "\"expectedSigningCertSha256\":" + hashJson + "}\n",
            )
            logger.lifecycle("RASP build config ($buildType): signing certificate SHA-256 ${hash ?: "not available"}")
        }
    }
    tasks.matching { it.name == "compileFlutterBuild$variant" }.configureEach { dependsOn(generate) }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
