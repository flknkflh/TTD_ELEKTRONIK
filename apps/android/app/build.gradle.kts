plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "id.example.pqcsign"
    compileSdk = 36
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "id.example.pqcsign"
        minSdk = 29          // matches gomobile bind -androidapi 29 (Rencana V1 §21)
        targetSdk = 36
        versionCode = 3
        versionName = "0.3.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // arm64 only: the AAR ships jni/arm64-v8a/libgojni.so
        ndk { abiFilters += "arm64-v8a" }
    }

    // Release signing from CI secrets (Rencana V1 §21.3, §27): the keystore
    // never lives in the repo. If the env vars are absent the release build
    // stays unsigned (CI still produces an artifact for inspection).
    val ksPath = System.getenv("PQC_ANDROID_KEYSTORE")
    signingConfigs {
        if (ksPath != null && file(ksPath).exists()) {
            create("release") {
                storeFile = file(ksPath)
                storePassword = System.getenv("PQC_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("PQC_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("PQC_ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        buildConfig = true
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
    lint {
        abortOnError = false
    }
    packaging {
        resources.excludes += setOf("META-INF/LICENSE", "META-INF/LICENSE.txt", "META-INF/NOTICE", "META-INF/*.kotlin_module")
    }
}

dependencies {
    // Built by apps/android/build-aar.sh from example.internal/pqc-pdf-sign/core/mobilebridge
    implementation(group = "", name = "pqcsign", ext = "aar")

    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity:1.9.3")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0") // in-app QR scanner (verify screen)

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.json:json:20240303")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}

// The M1 on-device spike (SpikeRunner + generated lab fixtures) has been
// removed — the app now does real enrolment against the server. If you have a
// stale src/main/assets/lab/ from an earlier build, delete it.
