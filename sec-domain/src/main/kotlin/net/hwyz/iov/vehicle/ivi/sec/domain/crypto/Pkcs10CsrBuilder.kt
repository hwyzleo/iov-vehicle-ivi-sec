package net.hwyz.iov.vehicle.ivi.sec.domain.crypto

import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * PKCS#10 certification request builder (IVI-SEC-SPEC US-002 / D-008).
 *
 * The request mirrors the TBOX device certificate profile:
 * subject CN/OU/O/C, SAN URI urn:ecu-uid, KeyUsage and ExtendedKeyUsage are carried as a PKCS#9
 * extensionRequest attribute. The request info is signed by the non-exportable device key with
 * SHA256withECDSA, so the signer callback is the only place the private key is used.
 */
object Pkcs10CsrBuilder {

    private const val OID_COMMON_NAME = "2.5.4.3"
    private const val OID_ORGANIZATIONAL_UNIT = "2.5.4.11"
    private const val OID_ORGANIZATION = "2.5.4.10"
    private const val OID_COUNTRY = "2.5.4.6"

    private const val OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14"
    private const val OID_SUBJECT_ALT_NAME = "2.5.29.17"
    private const val OID_KEY_USAGE = "2.5.29.15"
    private const val OID_EXTENDED_KEY_USAGE = "2.5.29.37"
    private const val OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    private const val OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"

    private const val TAG_URI = 0x86
    private const val KEY_USAGE_DIGITAL_SIGNATURE = 0x80
    private const val KEY_USAGE_KEY_AGREEMENT = 0x08

    private const val PEM_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----"
    private const val PEM_END = "-----END CERTIFICATE REQUEST-----"

    /**
     * Builds the DER encoded request.
     *
     * @param publicKeySpkiDer X.509 SubjectPublicKeyInfo of the device key.
     * @param profile subject and requested extensions; the default matches the TBOX profile.
     * @param signer signs the certification request info with the device key (SHA256withECDSA).
     */
    fun build(
        publicKeySpkiDer: ByteArray,
        profile: CsrProfile,
        signer: (ByteArray) -> ByteArray,
    ): ByteArray {
        require(publicKeySpkiDer.isNotEmpty()) { "public key is empty" }

        val subject = Der.sequence(
            rdn(OID_COMMON_NAME, profile.commonName),
            rdn(OID_ORGANIZATIONAL_UNIT, profile.organizationalUnit),
            rdn(OID_ORGANIZATION, profile.organization),
            rdn(OID_COUNTRY, profile.country),
        )

        val subjectAltName = extension(
            OID_SUBJECT_ALT_NAME,
            // GeneralNames ::= SEQUENCE OF GeneralName; URI is [6] IMPLICIT IA5String.
            Der.sequence(Der.tlv(TAG_URI, profile.sanUri.toByteArray(StandardCharsets.US_ASCII))),
        )
        val keyUsageBits = KEY_USAGE_DIGITAL_SIGNATURE or
            (if (profile.requestKeyAgreement) KEY_USAGE_KEY_AGREEMENT else 0)
        val keyUsage = extension(
            OID_KEY_USAGE,
            Der.bitString(byteArrayOf(keyUsageBits.toByte())),
        )
        val extendedKeyUsage = extension(
            OID_EXTENDED_KEY_USAGE,
            Der.sequence(Der.oid(OID_CLIENT_AUTH)),
        )

        // Attribute ::= SEQUENCE { extensionRequest OID, SET { SEQUENCE OF Extension } }
        val extensionRequest = Der.sequence(subjectAltName, keyUsage, extendedKeyUsage)
        val attribute = Der.sequence(
            Der.oid(OID_EXTENSION_REQUEST),
            Der.set(extensionRequest),
        )
        val attributes = Der.contextConstructed(0, attribute)

        val requestInfo = Der.sequence(
            Der.integer(0),
            subject,
            publicKeySpkiDer,
            attributes,
        )
        val signature = signer(requestInfo)
        require(signature.isNotEmpty()) { "device key returned an empty signature" }
        val signatureAlgorithm = Der.sequence(Der.oid(OID_ECDSA_WITH_SHA256))
        return Der.sequence(requestInfo, signatureAlgorithm, Der.bitString(signature))
    }

    /** PEM wrapper used by the provisioning export channel (file / QR / adb). */
    fun toPem(der: ByteArray): String {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
        return "$PEM_BEGIN\n$body\n$PEM_END\n"
    }

    private fun rdn(oid: String, value: String): ByteArray =
        Der.set(Der.sequence(Der.oid(oid), Der.utf8(value)))

    private fun extension(oid: String, value: ByteArray): ByteArray =
        Der.sequence(Der.oid(oid), Der.octetString(value))
}
