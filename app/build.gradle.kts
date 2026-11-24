plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "net.hwyz.iov.vehicle.ivi.sec"
    compileSdk = 34

    defaultConfig {
        applicationId = "net.hwyz.iov.vehicle.ivi.sec"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // Deployment values only; security policy lives in SecConfig and the domain.
        buildConfigField("String", "SGW_BASE_URL", "\"https://sgw.openiov.top\"")
        buildConfigField("String", "CIAM_CLIENT_ID", "\"ivi-capp\"")
        buildConfigField("String", "DEVICE_KEY_ALIAS", "\"ivi-sec-device-v1\"")
        // MOCK until Xiaomi exposes the real SE/HSM UID; must be provisioned per device before production.
        buildConfigField("String", "HSM_UID", "\"00000005AA0000000000000000000001\"")
        buildConfigField(
            "String",
            "DEVICE_SCOPES",
            "\"vehicle.activation vehicle.privacy.report\"",
        )
        buildConfigField(
            "String",
            "CALLER_WHITELIST",
            "\"net.hwyz.iov.vehicle.ivi.acc.demo,net.hwyz.iov.vehicle.ivi.ivai.demo\"",
        )

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        getByName("debug") {
            // Instrumentation only: the test APK shares the debug signature but is not a production caller.
            buildConfigField(
                "String",
                "CALLER_WHITELIST",
                "\"net.hwyz.iov.vehicle.ivi.acc.demo,net.hwyz.iov.vehicle.ivi.ivai.demo,net.hwyz.iov.vehicle.ivi.sec.test\"",
            )
        }
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        buildConfig = true
        aidl = true
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }
}

// Artifact name: the module is `app`, but the shipped binary is the IVI SEC service APK.
// Produces ivi-sec-debug.apk / ivi-sec-release.apk instead of app-<variant>.apk.
base {
    archivesName.set("ivi-sec")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":sec-api"))
    implementation(project(":sec-domain"))
    implementation(project(":sec-data"))

    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.activity.ktx)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.junit4)
    testImplementation(libs.junit.vintage.engine)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.bouncycastle.bcpkix)
    androidTestImplementation(libs.bouncycastle.bcprov)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
