package net.hwyz.iov.vehicle.ivi.sec.support

import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceProof
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceTokenPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.KeySecurityLevel
import net.hwyz.iov.vehicle.ivi.sec.domain.port.SecMetaStore
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome

/** Minimal app-side fakes for Robolectric and JVM tests. */
class InMemoryDeviceKeyPort(
    var keyPresent: Boolean = false,
    var chain: List<ByteArray>? = null,
    var state: SecState = SecState.NOT_PROVISIONED,
) : DeviceKeyPort {
    override fun exists(alias: String): Boolean = keyPresent

    override fun generateEcP256(alias: String): ByteArray {
        keyPresent = true
        return byteArrayOf(1, 2, 3)
    }

    override fun publicKeyEncoded(alias: String): ByteArray? =
        if (keyPresent) byteArrayOf(1, 2, 3) else null

    override fun signSha256Ecdsa(alias: String, data: ByteArray): ByteArray = ByteArray(8) { 7 }

    override fun certificateChainDer(alias: String): List<ByteArray>? = chain

    override fun importCertificateChain(alias: String, chainDer: List<ByteArray>) {
        chain = chainDer
    }

    override fun securityLevel(alias: String): KeySecurityLevel = KeySecurityLevel.SOFTWARE
}

class InMemoryMetaStore(var meta: SecMeta = SecMeta()) : SecMetaStore {
    override suspend fun read(): SecMeta = meta

    override suspend fun write(meta: SecMeta) {
        this.meta = meta
    }
}

class FixedCallerVerifier(
    private val packageName: String = "net.hwyz.iov.vehicle.ivi.acc.demo",
    private val signedByService: Boolean = true,
) : CallerVerifier {
    override fun describe(uid: Int): CallerDescriptor =
        CallerDescriptor(uid, packageName, "sig", signedByService)
}

class FixedTokenPort(
    private val outcome: TokenIssueOutcome = TokenIssueOutcome.Issued("token", 900, null),
) : DeviceTokenPort {
    override suspend fun request(proof: DeviceProof, scopes: List<String>): TokenIssueOutcome = outcome
}
