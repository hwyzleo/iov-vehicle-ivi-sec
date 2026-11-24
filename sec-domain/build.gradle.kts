plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Pure Kotlin/JVM domain: no Android SDK, no UI, no network library.
kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.kotlinx.coroutines.test)
    // BouncyCastle is a test-only oracle for the hand written PKCS#10 encoder.
    testImplementation(libs.bouncycastle.bcpkix)
    testImplementation(libs.bouncycastle.bcprov)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
