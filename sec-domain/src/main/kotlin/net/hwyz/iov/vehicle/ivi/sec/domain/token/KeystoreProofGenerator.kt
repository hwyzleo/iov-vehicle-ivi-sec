package net.hwyz.iov.vehicle.ivi.sec.domain.token

import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceProof
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceKeyPort
import java.security.SecureRandom
import java.util.Base64

/** Supplies a fresh proof for every token request; nonces are never reused (US-004). */
fun interface ProofGenerator {
    suspend fun generate(): DeviceProof
}

/**
 * KEY_SIGNATURE proof: a 32 byte SecureRandom nonce signed by the device key (D-003).
 *
 * The nonce and the signature never reach a log sink.
 */
class KeystoreProofGenerator(
    private val keys: DeviceKeyPort,
    private val alias: String,
    private val deviceId: String?,
    private val nonceSizeBytes: Int = 32,
    private val random: SecureRandom = SecureRandom(),
) : ProofGenerator {

    override suspend fun generate(): DeviceProof {
        val nonce = ByteArray(nonceSizeBytes).also(random::nextBytes)
        val signature = keys.signSha256Ecdsa(alias, nonce)
        return DeviceProof(
            deviceId = deviceId,
            proofType = PROOF_TYPE,
            proofBase64 = Base64.getEncoder().encodeToString(signature),
            nonceBase64 = Base64.getEncoder().encodeToString(nonce),
        )
    }

    companion object {
        const val PROOF_TYPE = "KEY_SIGNATURE"
    }
}
