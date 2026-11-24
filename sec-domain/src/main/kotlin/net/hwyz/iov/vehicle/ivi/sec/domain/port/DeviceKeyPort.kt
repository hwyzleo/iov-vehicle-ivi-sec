package net.hwyz.iov.vehicle.ivi.sec.domain.port

/** Backing security level of the device key, reported truthfully (C-001). */
enum class KeySecurityLevel {
    TEE,
    SOFTWARE,
}

/**
 * Device key and certificate chain custody (IVI-SEC-SPEC D-002 / D-009).
 *
 * Implementations must keep the private key non-exportable; only the public key and certificate
 * chain may leave the platform store.
 */
interface DeviceKeyPort {
    fun exists(alias: String): Boolean

    /** Generates an EC P-256 signing key and returns the X.509 SubjectPublicKeyInfo DER. */
    fun generateEcP256(alias: String): ByteArray

    fun publicKeyEncoded(alias: String): ByteArray?

    /** SHA256withECDSA over [data]; throws when the key is missing or unusable. */
    fun signSha256Ecdsa(alias: String, data: ByteArray): ByteArray

    /** Certificate chain in DER, leaf first; null when no chain is installed. */
    fun certificateChainDer(alias: String): List<ByteArray>?

    /** Associates a certificate chain with the existing private key (leaf first). */
    fun importCertificateChain(alias: String, chainDer: List<ByteArray>)

    fun securityLevel(alias: String): KeySecurityLevel
}
