plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

// Published contract module: callers depend on this AAR only, never on the implementation modules.
android {
    namespace = "net.hwyz.iov.vehicle.ivi.sec.api"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
    }

    publishing {
        // The AAR is the only artifact callers need; implementation modules stay unpublished.
        singleVariant("release") {
            withSourcesJar()
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        aidl = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.junit4)
    testImplementation(libs.junit.vintage.engine)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

// The AGP software component is registered at the end of evaluation, so the publication must be too.
afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                groupId = "net.hwyz.iov.vehicle.ivi.sec"
                artifactId = "sec-api"
                version = "0.1.0-SNAPSHOT"
                from(components["release"])
            }
        }
    }
}
