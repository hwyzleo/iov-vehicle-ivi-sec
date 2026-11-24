package net.hwyz.iov.vehicle.ivi.sec.domain.crypto

import net.hwyz.iov.vehicle.ivi.sec.domain.support.newEcKeyPair
import net.hwyz.iov.vehicle.ivi.sec.domain.support.selfSignedCertificate
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** US-002: certificate chain parsing and ordering validation. */
class CertificateChainCodecTest {

    @Test
    @DisplayName("PEM bundle and raw DER produce the same certificate")
    fun parsesPemAndDer() {
        val keyPair = newEcKeyPair()
        val certificate = selfSignedCertificate(keyPair, "SN-TEST-001")
        val fromDer = CertificateChainCodec.parse(certificate.encoded)
        val fromPem = CertificateChainCodec.parse(
            CertificateChainCodec.toPem(listOf(certificate.encoded)).toByteArray(),
        )

        assertEquals(1, fromDer.size)
        assertEquals(1, fromPem.size)
        assertEquals(certificate, fromDer.first())
        assertEquals(certificate, fromPem.first())
        assertTrue(CertificateChainCodec.fingerprintSha256Hex(certificate).matches(Regex("[0-9A-F]{64}")))
    }

    @Test
    @DisplayName("A leaf signed by a CA is ordered; a reversed chain is not")
    fun validatesChainOrder() {
        val ca = newEcKeyPair()
        val leaf = newEcKeyPair()
        val caCertificate = selfSignedCertificate(ca, "Test CA")
        val leafCertificate = selfSignedCertificate(
            keyPair = leaf,
            commonName = "SN-TEST-001",
            issuerKeyPair = ca,
            issuerCommonName = "Test CA",
        )
        val chain = listOf(leafCertificate, caCertificate)
        assertTrue(CertificateChainCodec.isChainOrdered(chain))
        assertFalse(CertificateChainCodec.isChainOrdered(chain.reversed()))
    }

    @Test
    @DisplayName("Garbage input is rejected instead of being accepted silently")
    fun rejectsGarbage() {
        assertFailsWith<IllegalArgumentException> {
            CertificateChainCodec.parse("not a certificate".toByteArray())
        }
        assertFailsWith<IllegalArgumentException> {
            CertificateChainCodec.parse(ByteArray(0))
        }
        assertFailsWith<IllegalArgumentException> {
            CertificateChainCodec.parseDerList(listOf(byteArrayOf(0x30, 0x01, 0x00)))
        }
    }
}
