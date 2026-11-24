package net.hwyz.iov.vehicle.ivi.sec.domain.support

import net.hwyz.iov.vehicle.ivi.sec.domain.admission.CallerPolicy
import net.hwyz.iov.vehicle.ivi.sec.domain.admission.RateLimiter
import net.hwyz.iov.vehicle.ivi.sec.domain.audit.AuditRingBuffer
import net.hwyz.iov.vehicle.ivi.sec.domain.clock.Clock
import net.hwyz.iov.vehicle.ivi.sec.domain.config.SecConfig
import net.hwyz.iov.vehicle.ivi.sec.domain.IviSecFacade
import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceProof
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditEntry
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditSink
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceTokenPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.KeySecurityLevel
import net.hwyz.iov.vehicle.ivi.sec.domain.port.SecMetaStore
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceScopes
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceTokenCoordinator
import net.hwyz.iov.vehicle.ivi.sec.domain.token.KeystoreProofGenerator
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger

fun newEcKeyPair(): KeyPair =
    KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

fun sign(keyPair: KeyPair, data: ByteArray): ByteArray =
    Signature.getInstance("SHA256withECDSA").run {
        initSign(keyPair.private)
        update(data)
        sign()
    }

fun selfSignedCertificate(
    keyPair: KeyPair,
    commonName: String,
    notBefore: Date = Date(System.currentTimeMillis() - 60_000),
    notAfter: Date = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1_000),
    issuerKeyPair: KeyPair = keyPair,
    issuerCommonName: String = commonName,
): X509Certificate {
    val builder = JcaX509v3CertificateBuilder(
        X500Name("CN=$issuerCommonName"),
        BigInteger.valueOf(System.nanoTime()),
        notBefore,
        notAfter,
        X500Name("CN=$commonName"),
        keyPair.public,
    )
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.private)
    return JcaX509CertificateConverter().getCertificate(builder.build(signer))
}

class FakeClock(var now: Long = 1_700_000_000_000L) : Clock {
    override fun nowEpochMillis(): Long = now
}

class InMemoryMetaStore(initial: SecMeta = SecMeta()) : SecMetaStore {
    var meta: SecMeta = initial
    var writes: Int = 0

    override suspend fun read(): SecMeta = meta

    override suspend fun write(meta: SecMeta) {
        this.meta = meta
        writes++
    }
}

class FakeDeviceKeyPort(val keyPair: KeyPair = newEcKeyPair()) : DeviceKeyPort {
    var keyPresent = false
    var chain: List<ByteArray>? = null
    var signFailure: Exception? = null
    var importFailure: Exception? = null
    var generationCount = 0

    override fun exists(alias: String): Boolean = keyPresent

    override fun generateEcP256(alias: String): ByteArray {
        keyPresent = true
        generationCount++
        return keyPair.public.encoded
    }

    override fun publicKeyEncoded(alias: String): ByteArray? =
        if (keyPresent) keyPair.public.encoded else null

    override fun signSha256Ecdsa(alias: String, data: ByteArray): ByteArray {
        signFailure?.let { throw it }
        check(keyPresent) { "no key" }
        return sign(keyPair, data)
    }

    override fun certificateChainDer(alias: String): List<ByteArray>? = chain

    override fun importCertificateChain(alias: String, chainDer: List<ByteArray>) {
        importFailure?.let { throw it }
        check(keyPresent) { "no key" }
        chain = chainDer
    }

    override fun securityLevel(alias: String): KeySecurityLevel = KeySecurityLevel.SOFTWARE

    fun install(certificate: X509Certificate) {
        keyPresent = true
        chain = listOf(certificate.encoded)
    }
}

class FakeCallerVerifier(
    private val packages: Map<Int, String> = mapOf(ALLOWED_UID to ALLOWED_PACKAGE),
    private val signedByService: Boolean = true,
) : CallerVerifier {
    override fun describe(uid: Int): CallerDescriptor {
        val packageName = packages[uid]
        return CallerDescriptor(
            uid = uid,
            packageName = packageName,
            signatureSha256 = if (signedByService) "sig" else "other",
            signedByService = signedByService && packageName != null,
        )
    }

    companion object {
        const val ALLOWED_UID = 10_100
        const val ALLOWED_PACKAGE = "net.hwyz.iov.vehicle.ivi.acc.demo"
    }
}

class RecordingAuditSink : AuditSink {
    private val entries = mutableListOf<AuditEntry>()

    override fun record(entry: AuditEntry) {
        synchronized(entries) { entries += entry }
    }

    fun snapshot(): List<AuditEntry> = synchronized(entries) { entries.toList() }
}

class FakeTokenPort : DeviceTokenPort {
    val outcomes = ArrayDeque<TokenIssueOutcome>()
    val calls = AtomicInteger(0)
    var delayMillis: Long = 0
    var lastProof: DeviceProof? = null
    var lastScopes: List<String>? = null

    fun enqueue(outcome: TokenIssueOutcome) {
        synchronized(outcomes) { outcomes.addLast(outcome) }
    }

    override suspend fun request(proof: DeviceProof, scopes: List<String>): TokenIssueOutcome {
        calls.incrementAndGet()
        lastProof = proof
        lastScopes = scopes
        if (delayMillis > 0) kotlinx.coroutines.delay(delayMillis)
        synchronized(outcomes) { outcomes.removeFirstOrNull() }?.let { return it }
        return TokenIssueOutcome.Issued(
            accessToken = "token-${calls.get()}",
            expiresInSeconds = 900,
            scope = scopes.joinToString(" "),
        )
    }
}

/** Facade wired with in-memory fakes; every test can override one seam. */
class FacadeFixture(
    val clock: FakeClock = FakeClock(),
    val keys: FakeDeviceKeyPort = FakeDeviceKeyPort(),
    val metaStore: InMemoryMetaStore = InMemoryMetaStore(),
    val tokenPort: FakeTokenPort = FakeTokenPort(),
    val audit: RecordingAuditSink = RecordingAuditSink(),
    val verifier: FakeCallerVerifier = FakeCallerVerifier(),
    val deviceId: String? = "SN-TEST-001",
    val hsmUid: String? = MOCK_HSM_UID,
    val signLimit: Int = 30,
    val tokenLimit: Int = 12,
) {
    val coordinator = DeviceTokenCoordinator(
        port = tokenPort,
        proofGenerator = KeystoreProofGenerator(keys, ALIAS, deviceId),
        scopes = DeviceScopes(listOf(SCOPE_DEVICE, SCOPE_SECOND)),
        clock = clock,
        issuePermit = { rateLimiter.tryAcquireToken() },
    )
    val rateLimiter = RateLimiter(clock, signLimit, tokenLimit)

    val facade = IviSecFacade(
        keys = keys,
        metaStore = metaStore,
        tokens = coordinator,
        deviceIdProvider = { deviceId },
        callerVerifier = verifier,
        callerPolicy = CallerPolicy(setOf(FakeCallerVerifier.ALLOWED_PACKAGE)),
        rateLimiter = rateLimiter,
        audit = audit,
        clock = clock,
        config = SecConfig(keyAlias = ALIAS, hsmUid = hsmUid),
    )

    /** Puts the fixture into ISSUED_PENDING_CLOUD with a valid self-signed certificate. */
    fun provisionValidCertificate(): X509Certificate {
        val certificate = selfSignedCertificate(
            keyPair = keys.keyPair,
            commonName = deviceId ?: "SN-TEST-001",
            notBefore = Date(clock.now - 60_000),
            notAfter = Date(clock.now + 365L * 24 * 60 * 60 * 1_000),
        )
        keys.install(certificate)
        metaStore.meta = SecMeta(deviceId = deviceId, state = SecState.ISSUED_PENDING_CLOUD)
        return certificate
    }

    companion object {
        const val ALIAS = "ivi-sec-device-v1"
        const val MOCK_HSM_UID = "00000005AA0000000000000000000001"
        const val SCOPE_DEVICE = "vehicle.activation"
        const val SCOPE_SECOND = "vehicle.privacy.report"
    }
}
