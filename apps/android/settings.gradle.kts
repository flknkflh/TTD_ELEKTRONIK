pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        // The gomobile AAR is a flat file produced by apps/android/build-aar.sh.
        flatDir { dirs("app/libs") }
    }
}

rootProject.name = "pqc-pdf-sign-android"
include(":app")
