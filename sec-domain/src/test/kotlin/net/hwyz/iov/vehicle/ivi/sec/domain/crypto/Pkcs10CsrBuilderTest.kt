package net.hwyz.iov.vehicle.ivi.sec.domain.crypto

import net.hwyz.iov.vehicle.ivi.sec.domain.support.newEcKeyPair
import net.hwyz.iov.vehicle.ivi.sec.domain.support.sign
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** US-002: the CSR follows the TBOX device profile and is signed by the non-exportable key. */
class Pkcs10CsrBuilderTest {

    private val hsmUid = "00000005AA0000000000000000000001"

    private fun buildCsr(
        keyPair: java.security.KeyPair,
        profile: CsrProfile = CsrProfile(commonName = hsmUid),
    ): ByteArray = Pkcs10CsrBuilder.build(keyPair.public.encoded, profile) { info ->
        sign(keyPair, info)
    }

    @Test
    @DisplayName("CSR parses, verifies, and carries the TBOX subject profile")
    fun buildsTboxProfileCsr() {
        val keyPair = newEcKeyPair()
        val der = buildCsr(keyPair)
        val request = PKCS10CertificationRequest(der)

        assertEquals(
            "CN=$hsmUid,OU=IVI-TSP,O=OpenIOV,C=CN",
            request.subject.toString(),
        )
        assertTrue(
            request.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public)),
            "CSR signature must verify with the device key",
        )
        val encodedKey = SubjectPublicKeyInfo.getInstance(request.subjectPublicKeyInfo).encoded
        assertTrue(encodedKey.contentEquals(keyPair.public.encoded), "CSR must embed the device public key")
    }

    @Test
    @DisplayName("CSR requests SAN urn:ecu-uid, digitalSignature+keyAgreement and clientAuth only")
    fun requestsTboxExtensions() {
        val keyPair = newEcKeyPair()
        val request = PKCS10CertificationRequest(buildCsr(keyPair))
        val extensions = assertNotNull(request.requestedExtensions)

        val sanExtension = assertNotNull(extensions.getExtension(Extension.subjectAlternativeName))
        val san = GeneralNames.getInstance(sanExtension.parsedValue)
        assertEquals(1, san.names.size)
        assertEquals("urn:ecu-uid:$hsmUid", (san.names.single().name as DERIA5String).string)

        val keyUsage = KeyUsage.fromExtensions(extensions)
        assertTrue(keyUsage.hasUsages(KeyUsage.digitalSignature))
        assertTrue(keyUsage.hasUsages(KeyUsage.keyAgreement))

        val eku = ExtendedKeyUsage.fromExtensions(extensions)
        assertEquals(listOf(KeyPurposeId.id_kp_clientAuth), eku.usages.toList())

        assertNull(extensions.getExtension(Extension.basicConstraints), "CSR must not request CA intent")
        assertTrue(!sanExtension.isCritical)
        assertTrue(!assertNotNull(extensions.getExtension(Extension.keyUsage)).isCritical)
        assertTrue(!assertNotNull(extensions.getExtension(Extension.extendedKeyUsage)).isCritical)
    }

    @Test
    @DisplayName("PEM wrapper contains the DER request")
    fun wrapsPem() {
        val keyPair = newEcKeyPair()
        val der = buildCsr(keyPair)
        val pem = Pkcs10CsrBuilder.toPem(der)
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
        assertTrue(pem.trimEnd().endsWith("-----END CERTIFICATE REQUEST-----"))
    }

    @Test
    @DisplayName("Long subjects exercise the DER long-form length encoding")
    fun supportsLongFormLength() {
        val keyPair = newEcKeyPair()
        val longName = "SN-" + "9".repeat(200)
        val der = Pkcs10CsrBuilder.build(
            keyPair.public.encoded,
            CsrProfile(commonName = longName),
        ) { info -> sign(keyPair, info) }
        val request = PKCS10CertificationRequest(der)
        assertTrue(request.subject.toString().contains("CN=$longName"))
        assertTrue(request.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public)))
    }

    @Test
    @DisplayName("Blank CN and empty key are rejected before signing")
    fun rejectsInvalidInput() {
        val keyPair = newEcKeyPair()
        assertFailsWith<IllegalArgumentException> { CsrProfile(commonName = " ") }
        assertFailsWith<IllegalArgumentException> {
            Pkcs10CsrBuilder.build(ByteArray(0), CsrProfile(commonName = "SN-1")) { info ->
                sign(keyPair, info)
            }
        }
    }
}
