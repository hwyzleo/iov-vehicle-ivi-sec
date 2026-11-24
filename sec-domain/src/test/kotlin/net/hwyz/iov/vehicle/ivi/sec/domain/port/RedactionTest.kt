package net.hwyz.iov.vehicle.ivi.sec.domain.port

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** A-008: tokens, nonces, signatures, keys and serials never reach the diagnostics sink. */
class RedactionTest {

    @Test
    @DisplayName("Sensitive keys are recognized in snake, kebab and camel case")
    fun recognizesSensitiveKeys() {
        listOf("token", "access_token", "accessToken", "nonce", "proof", "signature", "private_key", "deviceId", "serial")
            .forEach { assertTrue(Redaction.isSensitive(it), "$it must be sensitive") }
        listOf("state", "error", "cloud_code", "duration_ms", "package", "operation")
            .forEach { assertFalse(Redaction.isSensitive(it), "$it must stay visible") }
    }

    @Test
    @DisplayName("The recording logger drops sensitive attributes before rendering")
    fun recordingLoggerDropsSecrets() {
        val logger = RecordingDiagnosticsLogger()
        logger.event(
            "token.ok",
            "state" to "ACTIVE",
            "token" to "secret-token",
            "nonce" to "secret-nonce",
            "signature" to "secret-signature",
            "deviceId" to "SN-FULL-SERIAL",
            "scope_count" to "2",
        )
        val line = logger.entries.single()
        assertEquals("token.ok state=ACTIVE scope_count=2", line)
        assertFalse(line.contains("secret"))
        assertFalse(line.contains("SN-FULL-SERIAL"))
    }
}
