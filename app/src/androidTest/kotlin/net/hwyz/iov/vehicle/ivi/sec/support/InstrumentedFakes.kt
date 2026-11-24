package net.hwyz.iov.vehicle.ivi.sec.support

import net.hwyz.iov.vehicle.ivi.sec.domain.clock.Clock
import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceProof
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceTokenPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.KeySecurityLevel
import net.hwyz.iov.vehicle.ivi.sec.domain.port.SecMetaStore
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome

class InstrumentedClock(var now: Long = 1_700_000_000_000L) : Clock {
    override fun nowEpochMillis(): Long = now
}

class InstrumentedMetaStore(var meta: SecMeta = SecMeta()) : SecMetaStore {
    override suspend fun read(): SecMeta = meta

    override suspend fun write(meta: SecMeta) {
        this.meta = meta
    }
}

class InstrumentedDeviceKeyPort(
    var keyPresent: Boolean = false,
    var chain: List<ByteArray>? = null,
) : DeviceKeyPort {
    override fun exists(alias: String): Boolean = keyPresent

    override fun generateEcP256(alias: String): ByteArray {
        keyPresent = true
        return byteArrayOf(1, 2, 3)
    }

    override fun publicKeyEncoded(alias: String): ByteArray? =
        if (keyPresent) byteArrayOf(1, 2, 3) else null

    override fun signSha256Ecdsa(alias: String, data: ByteArray): ByteArray = ByteArray(8) { 9 }

    override fun certificateChainDer(alias: String): List<ByteArray>? = chain

    override fun importCertificateChain(alias: String, chainDer: List<ByteArray>) {
        chain = chainDer
    }

    override fun securityLevel(alias: String): KeySecurityLevel = KeySecurityLevel.SOFTWARE
}

class InstrumentedCallerVerifier(
    private val packageName: String?,
    private val signedByService: Boolean = true,
) : CallerVerifier {
    override fun describe(uid: Int): CallerDescriptor =
        CallerDescriptor(uid, packageName, "sig", signedByService && packageName != null)
}

class InstrumentedTokenPort : DeviceTokenPort {
    override suspend fun request(proof: DeviceProof, scopes: List<String>): TokenIssueOutcome =
        TokenIssueOutcome.Issued("instrumented-token", 900, scopes.joinToString(" "))
}
