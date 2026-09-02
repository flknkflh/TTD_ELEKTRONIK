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
        versionCode = 1
        versionName = "0.1-spike"
        // arm64 only: the AAR ships jni/arm64-v8a/libgojni.so
        ndk { abiFilters += "arm64-v8a" }
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
            // No release signing config in the spike — build debug APKs only.
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    lint {
        abortOnError = false
    }
    packaging {
        resources.excludes += setOf("META-INF/LICENSE", "META-INF/LICENSE.txt", "META-INF/NOTICE")
    }
}

dependencies {
    // Built by apps/android/build-aar.sh from example.internal/pqc-pdf-sign/core/mobilebridge
    implementation(group = "", name = "pqcsign", ext = "aar")
}

// --- spike test fixtures -----------------------------------------------------
// Generates app/src/main/assets/{sample*.pdf, lab/*} via `pqcsign-cli genpki`.
// Nothing here is committed: a lab private key must not enter git history
// (Rencana V1 §5.3, §9.3). Requires a Go 1.27 toolchain on PATH.
val assetsDir = layout.projectDirectory.dir("src/main/assets")
val cliModuleDir = rootProject.layout.projectDirectory.dir("../windows").asFile
val coreTestPdfDir = rootProject.layout.projectDirectory.dir("../../core/testpdf").asFile

val generateSpikeFixtures by tasks.registering(Exec::class) {
    description = "Generate lab PKI + sample PDFs into src/main/assets (spike only)"
    val labDir = assetsDir.dir("lab").asFile
    // Regenerated whenever this marker is missing; bump the name when the
    // fixture set changes so existing checkouts refresh.
    val marker = File(labDir, "unrelated-root.crt.pem")
    outputs.file(marker)
    onlyIf { !marker.exists() }
    doFirst { labDir.mkdirs() }
    workingDir = cliModuleDir
    commandLine(
        "go", "run", "./cmd/pqcsign-cli", "genpki",
        "--out", labDir.absolutePath,
        "--device-cn", "Android Spike Device",
        "--platform", "android",
    )
    doLast {
        File(labDir, "device-key.pkcs8.pem").let { if (it.exists()) it.renameTo(File(labDir, "device-test-key.pem")) }
        File(labDir, "device.csr.pem").delete()
        copy {
            from(coreTestPdfDir) { include("sample.pdf", "sample-multipage.pdf") }
            into(assetsDir)
        }
    }
}

tasks.named("preBuild") { dependsOn(generateSpikeFixtures) }
