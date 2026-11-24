package net.hwyz.iov.vehicle.ivi.sec.data.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.KeySecurityLevel
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec

/**
 * AndroidKeyStore backed device key custody (IVI-SEC-SPEC D-002).
 *
 * The EC P-256 private key is generated inside the platform store, is never exported, and is only
 * used through [Signature] handles. Certificate chains are attached to the same alias.
 */
class AndroidKeyStoreDeviceKeyPort(
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) },
) : DeviceKeyPort {

    override fun exists(alias: String): Boolean = keyStore.containsAlias(alias)

    override fun generateEcP256(alias: String): ByteArray {
        check(!keyStore.containsAlias(alias)) { "device key alias '$alias' already exists" }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE_P256))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()
        generator.initialize(spec)
        return generator.generateKeyPair().public.encoded
    }

    override fun publicKeyEncoded(alias: String): ByteArray? =
        keyStore.getCertificate(alias)?.publicKey?.encoded

    override fun signSha256Ecdsa(alias: String, data: ByteArray): ByteArray {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("device key alias '$alias' is not provisioned")
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(entry.privateKey)
        signature.update(data)
        return signature.sign()
    }

    override fun certificateChainDer(alias: String): List<ByteArray>? =
        keyStore.getCertificateChain(alias)?.map { it.encoded }

    override fun importCertificateChain(alias: String, chainDer: List<ByteArray>) {
        require(chainDer.isNotEmpty()) { "empty certificate chain" }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("device key alias '$alias' is not provisioned")
        val factory = CertificateFactory.getInstance("X.509")
        val chain = chainDer.map { der ->
            factory.generateCertificate(der.inputStream())
        }.toTypedArray<Certificate>()
        keyStore.setKeyEntry(alias, entry.privateKey, null, chain)
    }

    override fun securityLevel(alias: String): KeySecurityLevel {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: return KeySecurityLevel.SOFTWARE
        return runCatching {
            val factory = KeyFactory.getInstance(entry.privateKey.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
            if (keyInfo.isInsideSecureHardware) KeySecurityLevel.TEE else KeySecurityLevel.SOFTWARE
        }.getOrDefault(KeySecurityLevel.SOFTWARE)
    }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val CURVE_P256 = "secp256r1"
    }
}
