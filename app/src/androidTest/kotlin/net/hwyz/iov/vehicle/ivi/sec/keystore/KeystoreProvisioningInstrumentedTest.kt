package net.hwyz.iov.vehicle.ivi.sec.keystore

import net.hwyz.iov.vehicle.ivi.sec.data.keystore.AndroidKeyStoreDeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.IviSecFacade
import net.hwyz.iov.vehicle.ivi.sec.domain.admission.CallerPolicy
import net.hwyz.iov.vehicle.ivi.sec.domain.admission.RateLimiter
import net.hwyz.iov.vehicle.ivi.sec.domain.audit.AuditRingBuffer
import net.hwyz.iov.vehicle.ivi.sec.domain.config.SecConfig
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceScopes
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceTokenCoordinator
import net.hwyz.iov.vehicle.ivi.sec.domain.token.KeystoreProofGenerator
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedClock
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedMetaStore
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedTokenPort
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * Real AndroidKeyStore evidence for US-001 / US-002 / US-003 (A-001, A-002, A-003 partial).
 *
 * Runs on an emulator or device; TEE presence is reported, not assumed.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreProvisioningInstrumentedTest {

    private val alias = "ivi-sec-instrumented-test"
    private val deviceId = "SN-ANDROID-TEST"
    private val hsmUid = "00000005AA0000000000000000000001"
    private val uid = 10_200
    private val clock = InstrumentedClock()
    private val keyPort = AndroidKeyStoreDeviceKeyPort()
    private lateinit var metaStore: InstrumentedMetaStore
    private lateinit var facade: IviSecFacade

    @Before
    fun setUp() {
        deleteAlias()
        metaStore = InstrumentedMetaStore()
        facade = IviSecFacade(
            keys = keyPort,
            metaStore = metaStore,
            tokens = DeviceTokenCoordinator(
                port = InstrumentedTokenPort(),
                proofGenerator = KeystoreProofGenerator(keyPort, alias, deviceId),
                scopes = DeviceScopes(listOf("vehicle.activation")),
                clock = clock,
            ),
            deviceIdProvider = { deviceId },
            callerVerifier = CallerVerifier { CallerDescriptor(it, "net.hwyz.iov.vehicle.ivi.sec", "sig", true) },
            callerPolicy = CallerPolicy(setOf("net.hwyz.iov.vehicle.ivi.sec")),
            rateLimiter = RateLimiter(clock),
            audit = AuditRingBuffer(),
            clock = clock,
            config = SecConfig(keyAlias = alias, hsmUid = hsmUid),
        )
    }

    @After
    fun tearDown() {
        deleteAlias()
    }

    private fun deleteAlias() {
        val store = KeyStore.getInstance(AndroidKeyStoreDeviceKeyPort.ANDROID_KEYSTORE).apply { load(null) }
        runCatching { store.deleteEntry(alias) }
    }

    private fun keystore(): KeyStore =
        KeyStore.getInstance(AndroidKeyStoreDeviceKeyPort.ANDROID_KEYSTORE).apply { load(null) }

    private fun publicKeyOfKeystore(): PublicKey {
        val encoded = requireNotNull(keyPort.publicKeyEncoded(alias))
        return KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(encoded))
    }

    private fun newEcKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    private fun buildCertificate(
        subjectPublicKey: PublicKey,
        subjectCn: String,
        issuerKeyPair: KeyPair,
        issuerCn: String,
        notBefore: Date,
        notAfter: Date,
    ): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(
            X500Name("CN=$issuerCn"),
            BigInteger.valueOf(System.nanoTime()),
            notBefore,
            notAfter,
            X500Name("CN=$subjectCn"),
            subjectPublicKey,
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    @Test
    fun fullProvisioningFlowOnRealKeystore() = runBlocking {
        // 1. Key + CSR
        val csr = facade.requestCsr()
        assertEquals(hsmUid, csr.hsmUid)
        assertEquals(deviceId, csr.deviceId)
        assertTrue(keyPort.exists(alias))
        assertEquals(SecState.PROVISIONING, metaStore.meta.state)

        val request = PKCS10CertificationRequest(csr.csrDer)
        assertEquals("CN=$hsmUid,OU=IVI-TSP,O=OpenIOV,C=CN", request.subject.toString())
        val san = GeneralNames.getInstance(
            request.requestedExtensions.getExtension(Extension.subjectAlternativeName).parsedValue,
        )
        assertEquals(
            "urn:ecu-uid:$hsmUid",
            (san.names.single().name as DERIA5String).string,
        )
        val publicKey = publicKeyOfKeystore()
        assertTrue(
            "CSR signature must verify with the keystore public key",
            request.isSignatureValid(
                org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(publicKey),
            ),
        )

        // The private key is a non-exportable keystore handle.
        val privateKey = keystore().getKey(alias, null) as PrivateKey
        assertNull("AndroidKeyStore private keys must not be exportable", privateKey.encoded)

        // 2. Certificate issued by a software CA over the keystore public key.
        val ca = newEcKeyPair()
        val now = clock.nowEpochMillis()
        val caCertificate = buildCertificate(
            subjectPublicKey = ca.public,
            subjectCn = "IVI-SEC Instrumented CA",
            issuerKeyPair = ca,
            issuerCn = "IVI-SEC Instrumented CA",
            notBefore = Date(now - 60_000),
            notAfter = Date(now + 365L * 24 * 60 * 60 * 1_000),
        )
        val leaf = buildCertificate(
            subjectPublicKey = publicKey,
            subjectCn = deviceId,
            issuerKeyPair = ca,
            issuerCn = "IVI-SEC Instrumented CA",
            notBefore = Date(now - 60_000),
            notAfter = Date(now + 365L * 24 * 60 * 60 * 1_000),
        )

        // 3. A certificate for another key is rejected.
        val foreignLeaf = buildCertificate(
            subjectPublicKey = newEcKeyPair().public,
            subjectCn = deviceId,
            issuerKeyPair = ca,
            issuerCn = "IVI-SEC Instrumented CA",
            notBefore = Date(now - 60_000),
            notAfter = Date(now + 365L * 24 * 60 * 60 * 1_000),
        )
        val mismatch = runCatching {
            facade.importCertificateChain(listOf(foreignLeaf.encoded, caCertificate.encoded))
        }.exceptionOrNull()
        assertTrue(mismatch is net.hwyz.iov.vehicle.ivi.sec.domain.SecException)
        assertEquals(
            SecErrorCode.CERT_INVALID,
            (mismatch as net.hwyz.iov.vehicle.ivi.sec.domain.SecException).error,
        )

        // 4. Import the correct chain and verify the state and the installed chain.
        val info = facade.importCertificateChain(listOf(leaf.encoded, caCertificate.encoded))
        assertEquals(SecState.ISSUED_PENDING_CLOUD, info.state)
        assertEquals(SecState.ISSUED_PENDING_CLOUD.code, facade.state(uid))
        assertNotNull(keyPort.certificateChainDer(alias))
        assertEquals(2, keyPort.certificateChainDer(alias)!!.size)

        // 5. Sign with the device key and verify against the installed certificate.
        val nonce = ByteArray(32) { (it + 1).toByte() }
        val signature = facade.signNonce(uid, nonce)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(leaf.publicKey)
        verifier.update(nonce)
        assertTrue("device signature must verify with the installed certificate", verifier.verify(signature))

        // 6. First token promotes to ACTIVE (cloud is faked here).
        val token = facade.deviceToken(uid, emptyList())
        assertTrue(token.accessToken.isNotEmpty())
        assertEquals(SecState.ACTIVE, metaStore.meta.state)

        // Security level is reported truthfully; emulators are normally SOFTWARE.
        println("AndroidKeyStore security level: ${keyPort.securityLevel(alias)}")
    }
}
