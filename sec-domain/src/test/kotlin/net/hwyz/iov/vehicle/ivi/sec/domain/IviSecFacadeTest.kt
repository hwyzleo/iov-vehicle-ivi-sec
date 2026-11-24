package net.hwyz.iov.vehicle.ivi.sec.domain

import kotlinx.coroutines.runBlocking
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditOperation
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditOutcome
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome
import net.hwyz.iov.vehicle.ivi.sec.domain.support.FacadeFixture
import net.hwyz.iov.vehicle.ivi.sec.domain.support.FakeCallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.domain.support.newEcKeyPair
import net.hwyz.iov.vehicle.ivi.sec.domain.support.selfSignedCertificate
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.security.Signature
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** US-001..US-006 acceptance paths at the domain boundary. */
class IviSecFacadeTest {

    private val uid = FakeCallerVerifier.ALLOWED_UID

    private suspend fun expectError(expected: SecErrorCode, block: suspend () -> Unit) {
        val error = assertFailsWith<SecException> { runBlocking { block() } }
        assertEquals(expected, error.error)
    }

    private fun validCertificate(
        fixture: FacadeFixture,
        notBeforeOffsetMillis: Long = -60_000,
        notAfterOffsetMillis: Long = 365L * 24 * 60 * 60 * 1_000,
    ): X509Certificate = selfSignedCertificate(
        keyPair = fixture.keys.keyPair,
        commonName = fixture.deviceId ?: "SN-TEST-001",
        notBefore = Date(fixture.clock.now + notBeforeOffsetMillis),
        notAfter = Date(fixture.clock.now + notAfterOffsetMillis),
    )

    @Test
    @DisplayName("No key means NOT_PROVISIONED and no proof is produced")
    fun notProvisionedFailsClosed() = runBlocking {
        val fixture = FacadeFixture()
        assertEquals(SecState.NOT_PROVISIONED.code, fixture.facade.state(uid))
        expectError(SecErrorCode.NOT_PROVISIONED) { fixture.facade.signNonce(uid, ByteArray(32)) }
        expectError(SecErrorCode.NOT_PROVISIONED) { fixture.facade.deviceToken(uid, emptyList()) }
    }

    @Test
    @DisplayName("Callers outside the allowlist are rejected and audited")
    fun rejectsForeignCaller() = runBlocking {
        val fixture = FacadeFixture()
        expectError(SecErrorCode.CALLER_REJECTED) { fixture.facade.state(424242) }
        val record = fixture.audit.snapshot().last()
        assertEquals(AuditOutcome.REJECTED, record.outcome)
        assertEquals(SecErrorCode.CALLER_REJECTED.code, record.reasonCode)
        assertEquals(AuditOperation.STATE_QUERY, record.operation)
    }

    @Test
    @DisplayName("CSR creation generates the EC key, persists the device id and is verifiable")
    fun createsCsr() = runBlocking {
        val fixture = FacadeFixture()
        val csr = fixture.facade.requestCsr()

        assertEquals(FacadeFixture.MOCK_HSM_UID, csr.hsmUid)
        assertEquals("SN-TEST-001", csr.deviceId)
        assertEquals(1, fixture.keys.generationCount)
        assertEquals(SecState.PROVISIONING, fixture.metaStore.meta.state)
        assertEquals("SN-TEST-001", fixture.metaStore.meta.deviceId)
        val request = PKCS10CertificationRequest(csr.csrDer)
        assertTrue(
            request.isSignatureValid(JcaContentVerifierProviderBuilder().build(fixture.keys.keyPair.public)),
        )

        // A second request reuses the existing key instead of rotating it silently.
        fixture.facade.requestCsr()
        assertEquals(1, fixture.keys.generationCount)
    }

    @Test
    @DisplayName("CSR subject and extensions match the TBOX device profile")
    fun csrProfileMatchesTbox() = runBlocking {
        val fixture = FacadeFixture()
        val csr = fixture.facade.requestCsr()
        val request = PKCS10CertificationRequest(csr.csrDer)

        assertEquals(
            "CN=${FacadeFixture.MOCK_HSM_UID},OU=IVI-TSP,O=OpenIOV,C=CN",
            request.subject.toString(),
        )
        val extensions = assertNotNull(request.requestedExtensions)
        val san = GeneralNames.getInstance(
            assertNotNull(extensions.getExtension(Extension.subjectAlternativeName)).parsedValue,
        )
        assertEquals(
            "urn:ecu-uid:${FacadeFixture.MOCK_HSM_UID}",
            (san.getNames().single().name as DERIA5String).string,
        )
        val keyUsage = KeyUsage.fromExtensions(extensions)
        assertTrue(keyUsage.hasUsages(KeyUsage.digitalSignature or KeyUsage.keyAgreement))
        val eku = ExtendedKeyUsage.fromExtensions(extensions)
        assertEquals(listOf(KeyPurposeId.id_kp_clientAuth), eku.usages.toList())
        assertNull(extensions.getExtension(Extension.basicConstraints))
    }

    @Test
    @DisplayName("CSR creation needs a provisioned HSM UID")
    fun csrRequiresHsmUid() = runBlocking {
        val fixture = FacadeFixture(hsmUid = null)
        expectError(SecErrorCode.INVALID_ARGUMENT) { fixture.facade.requestCsr() }
    }

    @Test
    @DisplayName("CSR creation does not require a device serial (deviceId is only for the token)")
    fun csrWorksWithoutDeviceSerial() = runBlocking {
        val fixture = FacadeFixture(deviceId = null)
        val csr = fixture.facade.requestCsr()
        assertEquals(FacadeFixture.MOCK_HSM_UID, csr.hsmUid)
        assertNull(csr.deviceId)
        assertTrue(csr.csrPem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
    }

    @Test
    @DisplayName("A certificate for another key is rejected and the identity stays unprovisioned")
    fun rejectsCertificateKeyMismatch() = runBlocking {
        val fixture = FacadeFixture()
        fixture.facade.requestCsr()
        val foreign = selfSignedCertificate(newEcKeyPair(), "SN-TEST-001", Date(fixture.clock.now), Date(fixture.clock.now + 86_400_000))

        expectError(SecErrorCode.CERT_INVALID) {
            fixture.facade.importCertificateChain(listOf(foreign.encoded))
        }
        assertEquals(SecState.PROVISIONING, fixture.metaStore.meta.state)
        assertTrue(fixture.keys.chain == null)
    }

    @Test
    @DisplayName("A CA-only bundle is rejected with the missing-leaf diagnosis")
    fun rejectsCaBundleWithoutLeaf() = runBlocking {
        val fixture = FacadeFixture()
        fixture.facade.requestCsr()
        // What the PKI console hands out when the issued device certificate is not exported.
        val ca = selfSignedCertificate(
            newEcKeyPair(),
            "OpenIOV Internal PKI Intermediate CA",
            Date(fixture.clock.now),
            Date(fixture.clock.now + 86_400_000),
        )

        val error = assertFailsWith<SecException> {
            fixture.facade.importCertificateChain(listOf(ca.encoded))
        }
        assertEquals(SecErrorCode.CERT_INVALID, error.error)
        assertTrue(error.reason!!.contains("must start with the leaf"))
        assertTrue(error.reason!!.contains("Intermediate CA"))
        assertEquals(SecState.PROVISIONING, fixture.metaStore.meta.state)
    }

    @Test
    @DisplayName("A valid chain that buries the leaf behind another certificate is diagnosed by position")
    fun reportsLeafPosition() = runBlocking {
        val fixture = FacadeFixture()
        fixture.facade.requestCsr()
        val deviceCertificate = validCertificate(fixture)
        // Ordered chain whose first entry is signed by the device key, so only the key check can fail.
        val other = selfSignedCertificate(
            newEcKeyPair(),
            "SN-OTHER-001",
            Date(fixture.clock.now),
            Date(fixture.clock.now + 86_400_000),
            issuerKeyPair = fixture.keys.keyPair,
            issuerCommonName = deviceCertificate.subjectX500Principal.name.removePrefix("CN="),
        )

        val error = assertFailsWith<SecException> {
            fixture.facade.importCertificateChain(listOf(other.encoded, deviceCertificate.encoded))
        }
        assertEquals(SecErrorCode.CERT_INVALID, error.error)
        assertTrue(error.reason!!.contains("entry #2"))
    }

    @Test
    @DisplayName("A three level chain (leaf, intermediate, root) imports in leaf-first order")
    fun importsThreeLevelChain() = runBlocking {
        val fixture = FacadeFixture()
        fixture.facade.requestCsr()
        val rootKey = newEcKeyPair()
        val intermediateKey = newEcKeyPair()
        val now = Date(fixture.clock.now)
        val inAYear = Date(fixture.clock.now + 365L * 24 * 60 * 60 * 1_000)
        val root = selfSignedCertificate(rootKey, "Test Root CA", now, inAYear)
        val intermediate = selfSignedCertificate(
            intermediateKey,
            "Test Intermediate CA",
            now,
            inAYear,
            issuerKeyPair = rootKey,
            issuerCommonName = "Test Root CA",
        )
        val leaf = selfSignedCertificate(
            fixture.keys.keyPair,
            "SN-TEST-001",
            now,
            inAYear,
            issuerKeyPair = intermediateKey,
            issuerCommonName = "Test Intermediate CA",
        )

        val info = fixture.facade.importCertificateChain(
            listOf(leaf.encoded, intermediate.encoded, root.encoded),
        )

        assertEquals(SecState.ISSUED_PENDING_CLOUD, info.state)
        assertEquals(3, fixture.keys.chain!!.size)
        assertEquals(leaf.encoded.toList(), fixture.keys.chain!!.first().toList())
    }

    @Test
    @DisplayName("An expired certificate is rejected at import")
    fun rejectsExpiredCertificateAtImport() = runBlocking {
        val fixture = FacadeFixture()
        fixture.facade.requestCsr()
        val expired = validCertificate(
            fixture,
            notBeforeOffsetMillis = -2L * 86_400_000,
            notAfterOffsetMillis = -86_400_000,
        )
        expectError(SecErrorCode.CERT_EXPIRED) {
            fixture.facade.importCertificateChain(listOf(expired.encoded))
        }
    }

    @Test
    @DisplayName("Import moves to ISSUED_PENDING_CLOUD, signing verifies, first token promotes to ACTIVE")
    fun provisioningAndSigningFlow() = runBlocking {
        val fixture = FacadeFixture()
        fixture.facade.requestCsr()
        val certificate = validCertificate(fixture)
        val info = fixture.facade.importCertificateChain(listOf(certificate.encoded))

        assertEquals(SecState.ISSUED_PENDING_CLOUD, info.state)
        assertEquals(SecState.ISSUED_PENDING_CLOUD.code, fixture.facade.state(uid))
        assertNotNull(info.certSn)
        assertEquals(SecErrorCode.OK.code, fixture.metaStore.meta.lastReasonCode)

        val nonce = ByteArray(32) { (it + 1).toByte() }
        val signature = fixture.facade.signNonce(uid, nonce)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(certificate.publicKey)
        verifier.update(nonce)
        assertTrue(verifier.verify(signature), "signature must verify with the installed certificate")

        val token = fixture.facade.deviceToken(uid, emptyList())
        assertTrue(token.accessToken.isNotEmpty())
        assertEquals(SecState.ACTIVE, fixture.metaStore.meta.state)
        assertEquals(1, fixture.tokenPort.calls.get())
    }

    @Test
    @DisplayName("Nonce length outside 16..128 bytes is rejected")
    fun rejectsInvalidNonceLength() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        expectError(SecErrorCode.INVALID_ARGUMENT) { fixture.facade.signNonce(uid, ByteArray(15)) }
        expectError(SecErrorCode.INVALID_ARGUMENT) { fixture.facade.signNonce(uid, ByteArray(129)) }
    }

    @Test
    @DisplayName("Sign requests are rate limited per caller")
    fun limitsSignRequests() = runBlocking {
        val fixture = FacadeFixture(signLimit = 2)
        fixture.provisionValidCertificate()
        fixture.facade.signNonce(uid, ByteArray(16))
        fixture.facade.signNonce(uid, ByteArray(16))
        expectError(SecErrorCode.RATE_LIMITED) { fixture.facade.signNonce(uid, ByteArray(16)) }
    }

    @Test
    @DisplayName("Token cache hit avoids another cloud issuance and promotes the state once")
    fun tokenCacheAndPromotion() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()

        val first = fixture.facade.deviceToken(uid, emptyList())
        val second = fixture.facade.deviceToken(uid, emptyList())

        assertEquals(first.accessToken, second.accessToken)
        assertEquals(1, fixture.tokenPort.calls.get())
        assertEquals(SecState.ACTIVE, fixture.metaStore.meta.state)
        assertTrue(fixture.metaStore.meta.lastIssuedAtEpochMillis > 0)
    }

    @Test
    @DisplayName("Token renewal happens inside the 5 minute window")
    fun renewsToken() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        fixture.facade.deviceToken(uid, emptyList())
        fixture.clock.now += 600_001
        fixture.facade.deviceToken(uid, emptyList())
        assertEquals(2, fixture.tokenPort.calls.get())
    }

    @Test
    @DisplayName("Token issuance is rate limited for the device; cache hits are free")
    fun limitsTokenIssuance() = runBlocking {
        val fixture = FacadeFixture(tokenLimit = 1)
        fixture.provisionValidCertificate()
        fixture.facade.deviceToken(uid, emptyList())
        fixture.facade.invalidateDeviceToken(uid)
        expectError(SecErrorCode.RATE_LIMITED) { fixture.facade.deviceToken(uid, emptyList()) }
        assertEquals(1, fixture.tokenPort.calls.get())
    }

    @Test
    @DisplayName("701327 blocks the identity and later calls fail without touching the cloud")
    fun cloudBlockingIsSticky() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        fixture.tokenPort.enqueue(TokenIssueOutcome.Failed(SecErrorCode.DEVICE_BLOCKED, "701327"))

        expectError(SecErrorCode.DEVICE_BLOCKED) { fixture.facade.deviceToken(uid, emptyList()) }
        assertEquals(SecState.BLOCKED, fixture.metaStore.meta.state)
        assertEquals(SecErrorCode.DEVICE_BLOCKED.code, fixture.metaStore.meta.lastReasonCode)

        expectError(SecErrorCode.DEVICE_BLOCKED) { fixture.facade.deviceToken(uid, emptyList()) }
        assertEquals(1, fixture.tokenPort.calls.get())
    }

    @Test
    @DisplayName("701329 is retried once and then reported as SESSION_CONFLICT")
    fun retriesSessionConflict() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        fixture.tokenPort.enqueue(TokenIssueOutcome.Failed(SecErrorCode.SESSION_CONFLICT, "701329"))
        fixture.tokenPort.enqueue(TokenIssueOutcome.Failed(SecErrorCode.SESSION_CONFLICT, "701329"))

        expectError(SecErrorCode.SESSION_CONFLICT) { fixture.facade.deviceToken(uid, emptyList()) }
        assertEquals(2, fixture.tokenPort.calls.get())
    }

    @Test
    @DisplayName("An account level scope is rejected before the cloud is called")
    fun rejectsAccountScope() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        expectError(SecErrorCode.INVALID_ARGUMENT) {
            fixture.facade.deviceToken(uid, listOf("user.profile"))
        }
        assertEquals(0, fixture.tokenPort.calls.get())
    }

    @Test
    @DisplayName("Invalidate forces a new proof and issuance")
    fun invalidatesToken() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        fixture.facade.deviceToken(uid, emptyList())
        fixture.facade.invalidateDeviceToken(uid)
        fixture.facade.deviceToken(uid, emptyList())
        assertEquals(2, fixture.tokenPort.calls.get())
    }

    @Test
    @DisplayName("An expired installed certificate blocks and reports CERT_EXPIRED")
    fun expiredCertificateBlocks() = runBlocking {
        val fixture = FacadeFixture()
        fixture.facade.requestCsr()
        val expired = validCertificate(
            fixture,
            notBeforeOffsetMillis = -2L * 86_400_000,
            notAfterOffsetMillis = -86_400_000,
        )
        fixture.keys.install(expired)
        fixture.metaStore.meta = SecMeta(
            deviceId = fixture.deviceId,
            state = SecState.ISSUED_PENDING_CLOUD,
            notAfterEpochMillis = expired.notAfter.time,
        )

        expectError(SecErrorCode.CERT_EXPIRED) { fixture.facade.deviceToken(uid, emptyList()) }
        assertEquals(SecState.BLOCKED, fixture.metaStore.meta.state)
        assertEquals(SecErrorCode.CERT_EXPIRED.code, fixture.metaStore.meta.lastReasonCode)
    }

    @Test
    @DisplayName("A key failure during signing reports KEY_UNAVAILABLE and moves to ERROR")
    fun keyFailureIsReported() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        fixture.keys.signFailure = IllegalStateException("keystore unavailable")

        expectError(SecErrorCode.KEY_UNAVAILABLE) { fixture.facade.signNonce(uid, ByteArray(32)) }
        assertEquals(SecState.ERROR, fixture.metaStore.meta.state)
    }

    @Test
    @DisplayName("An active identity must be reopened before a new CSR, then re-provisioning works")
    fun reopenFlow() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        fixture.facade.deviceToken(uid, emptyList())
        assertEquals(SecState.ACTIVE, fixture.metaStore.meta.state)

        expectError(SecErrorCode.CALLER_REJECTED) { fixture.facade.requestCsr() }
        assertEquals(SecState.PROVISIONING.code, fixture.facade.reopen())
        val csr = fixture.facade.requestCsr()
        assertTrue(csr.csrPem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
    }

    @Test
    @DisplayName("Provider snapshot exposes state and certificate dates only")
    fun providerSnapshotIsNonSecret() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        val snapshot = fixture.facade.providerSnapshot()

        assertEquals(SecState.ISSUED_PENDING_CLOUD.code, snapshot.state)
        assertEquals("SN-TEST-001", snapshot.deviceId)
        assertNotNull(snapshot.certSn)
        assertTrue(snapshot.notAfterEpochMillis > 0)
    }

    @Test
    @DisplayName("Successful and failed operations are audited with stable codes")
    fun auditsOperations() = runBlocking {
        val fixture = FacadeFixture()
        fixture.provisionValidCertificate()
        fixture.facade.deviceToken(uid, emptyList())
        expectError(SecErrorCode.INVALID_ARGUMENT) {
            fixture.facade.deviceToken(uid, listOf("user.profile"))
        }

        val entries = fixture.audit.snapshot()
        assertTrue(entries.any { it.operation == AuditOperation.GET_DEVICE_TOKEN && it.outcome == AuditOutcome.OK })
        assertTrue(
            entries.any {
                it.operation == AuditOperation.GET_DEVICE_TOKEN &&
                    it.outcome == AuditOutcome.FAILED &&
                    it.reasonCode == SecErrorCode.INVALID_ARGUMENT.code
            },
        )
        assertTrue(entries.all { it.uid == uid })
    }
}
