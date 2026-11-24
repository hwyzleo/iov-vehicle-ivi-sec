package net.hwyz.iov.vehicle.ivi.sec.domain

import net.hwyz.iov.vehicle.ivi.sec.domain.admission.CallerPolicy
import net.hwyz.iov.vehicle.ivi.sec.domain.admission.RateLimiter
import net.hwyz.iov.vehicle.ivi.sec.domain.clock.Clock
import net.hwyz.iov.vehicle.ivi.sec.domain.config.SecConfig
import net.hwyz.iov.vehicle.ivi.sec.domain.crypto.CertificateChainCodec
import net.hwyz.iov.vehicle.ivi.sec.domain.crypto.CsrProfile
import net.hwyz.iov.vehicle.ivi.sec.domain.crypto.Pkcs10CsrBuilder
import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceCertificateInfo
import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceTokenSnapshot
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditEntry
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditOperation
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditOutcome
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditSink
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.domain.port.KeySecurityLevel
import net.hwyz.iov.vehicle.ivi.sec.domain.port.NoOpDiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.domain.port.SecMetaStore
import net.hwyz.iov.vehicle.ivi.sec.domain.state.SecEvent
import net.hwyz.iov.vehicle.ivi.sec.domain.state.SecStateMachine
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceScopes
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceTokenCoordinator
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceTokenResult
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Date

/** Result of a CSR request; the PEM form is what the provisioning UI exports. */
data class CsrResult(
    /** HSM/ECU UID, CSR CN and SAN identity (same namespace as the TBOX). */
    val hsmUid: String,
    /** Device serial used for the device token; independent from the HSM UID. */
    val deviceId: String?,
    val csrDer: ByteArray,
    val csrPem: String,
)

/** Read-only state row served by the content provider (IVI-SEC-SPEC §4.7). */
data class ProviderSnapshot(
    val state: Int,
    val deviceId: String?,
    val certSn: String?,
    val notAfterEpochMillis: Long,
    val lastReasonCode: Int,
    val updatedAtEpochMillis: Long,
)

private data class Identity(
    val meta: SecMeta,
    val certificate: X509Certificate?,
    val fingerprintSha256: String?,
    val securityLevel: KeySecurityLevel,
)

/**
 * Security use cases behind the AIDL service and the provisioning UI (IVI-SEC-SPEC §6 / §7).
 *
 * Every caller facing method authorizes the caller, applies rate limits, checks the state and
 * certificate, and fails closed with a stable [SecException].
 */
class IviSecFacade(
    private val keys: DeviceKeyPort,
    private val metaStore: SecMetaStore,
    private val tokens: DeviceTokenCoordinator,
    private val deviceIdProvider: () -> String?,
    private val callerVerifier: CallerVerifier,
    private val callerPolicy: CallerPolicy,
    private val rateLimiter: RateLimiter,
    private val audit: AuditSink,
    private val clock: Clock = Clock.System,
    private val config: SecConfig = SecConfig(),
    private val logger: DiagnosticsLogger = NoOpDiagnosticsLogger,
    private val certificateParser: (ByteArray) -> X509Certificate = { der ->
        CertificateFactory.getInstance("X.509")
            .generateCertificate(der.inputStream()) as X509Certificate
    },
) {
    private val deviceScopes = DeviceScopes(config.deviceScopes)

    suspend fun state(callerUid: Int): Int {
        val startedAt = clock.nowEpochMillis()
        val caller = authorize(callerUid, AuditOperation.STATE_QUERY, startedAt)
        return try {
            val identity = loadIdentity()
            recordAudit(caller, AuditOperation.STATE_QUERY, AuditOutcome.OK, SecErrorCode.OK, startedAt)
            identity.meta.state.code
        } catch (error: SecException) {
            recordAudit(caller, AuditOperation.STATE_QUERY, AuditOutcome.FAILED, error.error, startedAt)
            throw error
        }
    }

    suspend fun deviceId(callerUid: Int): String? {
        val startedAt = clock.nowEpochMillis()
        val caller = authorize(callerUid, AuditOperation.STATE_QUERY, startedAt)
        return try {
            val identity = loadIdentity()
            recordAudit(caller, AuditOperation.STATE_QUERY, AuditOutcome.OK, SecErrorCode.OK, startedAt)
            identity.meta.deviceId
        } catch (error: SecException) {
            recordAudit(caller, AuditOperation.STATE_QUERY, AuditOutcome.FAILED, error.error, startedAt)
            throw error
        }
    }

    suspend fun certificateInfo(callerUid: Int): DeviceCertificateInfo {
        val startedAt = clock.nowEpochMillis()
        val caller = authorize(callerUid, AuditOperation.STATE_QUERY, startedAt)
        return try {
            val identity = loadIdentity()
            recordAudit(caller, AuditOperation.STATE_QUERY, AuditOutcome.OK, SecErrorCode.OK, startedAt)
            DeviceCertificateInfo(
                deviceId = identity.meta.deviceId,
                subject = identity.meta.subject,
                certSn = identity.meta.certSn,
                notBeforeEpochMillis = identity.meta.notBeforeEpochMillis,
                notAfterEpochMillis = identity.meta.notAfterEpochMillis,
                fingerprintSha256 = identity.fingerprintSha256,
                state = identity.meta.state,
            )
        } catch (error: SecException) {
            recordAudit(caller, AuditOperation.STATE_QUERY, AuditOutcome.FAILED, error.error, startedAt)
            throw error
        }
    }

    /** Signs [nonce] with the device key; the returned bytes are the SHA256withECDSA signature. */
    suspend fun signNonce(callerUid: Int, nonce: ByteArray): ByteArray {
        val startedAt = clock.nowEpochMillis()
        val caller = authorize(callerUid, AuditOperation.SIGN_NONCE, startedAt)
        try {
            if (nonce.size !in config.nonceMinLength..config.nonceMaxLength) {
                throw SecException(SecErrorCode.INVALID_ARGUMENT, "nonce length ${nonce.size}")
            }
            val callerKey = caller.packageName ?: caller.uid.toString()
            if (!rateLimiter.tryAcquireSign(callerKey)) {
                throw SecException(SecErrorCode.RATE_LIMITED, "sign limit")
            }
            val identity = loadIdentity()
            if (!identity.meta.state.tokenEligible) {
                throw SecException(errorForState(identity.meta.state, identity.meta), "state ${identity.meta.state}")
            }
            ensureCertificateValid(identity)
            val signature = try {
                keys.signSha256Ecdsa(config.keyAlias, nonce)
            } catch (error: Exception) {
                persistFailure(identity, SecErrorCode.KEY_UNAVAILABLE)
                throw SecException(SecErrorCode.KEY_UNAVAILABLE, "sign failed", error)
            }
            recordAudit(caller, AuditOperation.SIGN_NONCE, AuditOutcome.OK, SecErrorCode.OK, startedAt)
            logger.event("sign.ok", "state" to identity.meta.state.name)
            return signature
        } catch (error: SecException) {
            recordAudit(caller, AuditOperation.SIGN_NONCE, AuditOutcome.FAILED, error.error, startedAt)
            logger.event("sign.failed", "error" to error.error.name)
            throw error
        }
    }

    /** Returns a cached or freshly issued device token (single flight, in memory only). */
    suspend fun deviceToken(callerUid: Int, requestedScopes: List<String>): DeviceTokenSnapshot {
        val startedAt = clock.nowEpochMillis()
        val caller = authorize(callerUid, AuditOperation.GET_DEVICE_TOKEN, startedAt)
        try {
            val identity = loadIdentity()
            if (!identity.meta.state.tokenEligible) {
                throw SecException(errorForState(identity.meta.state, identity.meta), "state ${identity.meta.state}")
            }
            ensureCertificateValid(identity)
            return when (val result = tokens.token(requestedScopes)) {
                is DeviceTokenResult.Issued -> {
                    val now = clock.nowEpochMillis()
                    val nextState = if (identity.meta.state == SecState.ISSUED_PENDING_CLOUD) {
                        SecStateMachine.transition(SecState.ISSUED_PENDING_CLOUD, SecEvent.FIRST_TOKEN_ISSUED)
                    } else {
                        identity.meta.state
                    }
                    metaStore.write(
                        identity.meta.copy(
                            state = nextState,
                            lastReasonCode = SecErrorCode.OK.code,
                            lastIssuedAtEpochMillis = now,
                            updatedAtEpochMillis = now,
                        ),
                    )
                    recordAudit(caller, AuditOperation.GET_DEVICE_TOKEN, AuditOutcome.OK, SecErrorCode.OK, startedAt)
                    logger.event(
                        "token.ok",
                        "state" to nextState.name,
                        "scope_count" to result.token.scopes.size.toString(),
                    )
                    result.token
                }

                is DeviceTokenResult.Failed -> {
                    persistFailure(identity, result.error)
                    throw SecException(result.error, result.cloudCode ?: result.message)
                }
            }
        } catch (error: SecException) {
            recordAudit(caller, AuditOperation.GET_DEVICE_TOKEN, AuditOutcome.FAILED, error.error, startedAt)
            logger.event("token.failed", "error" to error.error.name)
            throw error
        }
    }

    suspend fun invalidateDeviceToken(callerUid: Int) {
        val startedAt = clock.nowEpochMillis()
        val caller = authorize(callerUid, AuditOperation.INVALIDATE_TOKEN, startedAt)
        try {
            tokens.invalidate()
            recordAudit(caller, AuditOperation.INVALIDATE_TOKEN, AuditOutcome.OK, SecErrorCode.OK, startedAt)
            logger.event("token.invalidated")
        } catch (error: SecException) {
            recordAudit(caller, AuditOperation.INVALIDATE_TOKEN, AuditOutcome.FAILED, error.error, startedAt)
            throw error
        }
    }

    /** Operator entry for re-provisioning; moves the state to PROVISIONING when allowed. */
    suspend fun reopen(): Int {
        val identity = loadIdentity()
        if (!SecStateMachine.canTransition(identity.meta.state, SecEvent.REOPEN_REQUESTED)) {
            throw SecException(SecErrorCode.CALLER_REJECTED, "reopen not allowed from ${identity.meta.state}")
        }
        val nextState = SecStateMachine.transition(identity.meta.state, SecEvent.REOPEN_REQUESTED)
        metaStore.write(identity.meta.copy(state = nextState, updatedAtEpochMillis = clock.nowEpochMillis()))
        return nextState.code
    }

    /**
     * Creates (or reuses) the device key and returns a PKCS#10 CSR. Allowed only while the identity
     * is not active; an active identity must be reopened first.
     */
    suspend fun requestCsr(): CsrResult {
        val startedAt = clock.nowEpochMillis()
        try {
            val identity = loadIdentity()
            if (identity.meta.state != SecState.NOT_PROVISIONED && identity.meta.state != SecState.PROVISIONING) {
                throw SecException(SecErrorCode.CALLER_REJECTED, "reopen required before CSR")
            }
            val hsmUid = config.hsmUid?.takeIf { it.isNotBlank() }
                ?: throw SecException(SecErrorCode.INVALID_ARGUMENT, "hsm uid unavailable")
            val deviceId = identity.meta.deviceId ?: deviceIdProvider()
            val publicKey = if (keys.exists(config.keyAlias)) {
                keys.publicKeyEncoded(config.keyAlias)
                    ?: throw SecException(SecErrorCode.KEY_UNAVAILABLE, "public key unavailable")
            } else {
                val generated = try {
                    keys.generateEcP256(config.keyAlias)
                } catch (error: Exception) {
                    throw SecException(SecErrorCode.KEY_UNAVAILABLE, "key generation failed", error)
                }
                val nextState = if (identity.meta.state == SecState.NOT_PROVISIONED) {
                    SecStateMachine.transition(SecState.NOT_PROVISIONED, SecEvent.KEY_GENERATED)
                } else {
                    SecStateMachine.transition(SecState.PROVISIONING, SecEvent.KEY_REGENERATED)
                }
                metaStore.write(
                    identity.meta.copy(
                        deviceId = deviceId ?: identity.meta.deviceId,
                        state = nextState,
                        updatedAtEpochMillis = clock.nowEpochMillis(),
                    ),
                )
                generated
            }
            val csrDer = try {
                val profile = CsrProfile(
                    commonName = hsmUid,
                    organizationalUnit = config.csrOrganizationalUnit,
                    organization = config.csrOrganization,
                    country = config.csrCountry,
                    sanUriPrefix = config.csrSanUriPrefix,
                )
                Pkcs10CsrBuilder.build(publicKey, profile) { info ->
                    keys.signSha256Ecdsa(config.keyAlias, info)
                }
            } catch (error: SecException) {
                throw error
            } catch (error: Exception) {
                throw SecException(SecErrorCode.KEY_UNAVAILABLE, "csr signing failed", error)
            }
            recordAudit(null, AuditOperation.PROVISION, AuditOutcome.OK, SecErrorCode.OK, startedAt)
            logger.event(
                "provision.csr_created",
                "key_security" to identity.securityLevel.name,
                "subject_profile" to "ivi-device",
            )
            return CsrResult(hsmUid, deviceId, csrDer, Pkcs10CsrBuilder.toPem(csrDer))
        } catch (error: SecException) {
            recordAudit(null, AuditOperation.PROVISION, AuditOutcome.FAILED, error.error, startedAt)
            logger.event("provision.csr_failed", "error" to error.error.name)
            throw error
        }
    }

    /** Validates and installs the certificate chain returned by the PKI channel. */
    suspend fun importCertificateChain(chainDer: List<ByteArray>): DeviceCertificateInfo {
        val startedAt = clock.nowEpochMillis()
        try {
            val identity = loadIdentity()
            if (!keys.exists(config.keyAlias)) {
                throw SecException(SecErrorCode.NOT_PROVISIONED, "no device key")
            }
            if (identity.meta.state != SecState.PROVISIONING) {
                throw SecException(SecErrorCode.CALLER_REJECTED, "provisioning not started")
            }
            val chain = try {
                CertificateChainCodec.parseDerList(chainDer)
            } catch (error: Exception) {
                throw SecException(SecErrorCode.CERT_INVALID, "unparsable chain", error)
            }
            if (!CertificateChainCodec.isChainOrdered(chain)) {
                throw SecException(SecErrorCode.CERT_INVALID, "chain order or signature invalid")
            }
            val leaf = chain.first()
            val publicKey = keys.publicKeyEncoded(config.keyAlias)
                ?: throw SecException(SecErrorCode.KEY_UNAVAILABLE, "public key unavailable")
            if (!leaf.publicKey.encoded.contentEquals(publicKey)) {
                // The recurring operator error is pasting the CA bundle returned by the PKI without the
                // certificate issued for our CSR, so report what is actually wrong with the input.
                val matchIndex = chain.indexOfFirst { it.publicKey.encoded.contentEquals(publicKey) }
                val reason = if (matchIndex > 0) {
                    "device certificate is entry #${matchIndex + 1} of the input; the leaf must come first"
                } else {
                    "no certificate in the input matches the device key; the chain must start with " +
                        "the leaf issued for this device's CSR (input starts with '${leaf.subjectX500Principal.name}')"
                }
                throw SecException(SecErrorCode.CERT_INVALID, reason)
            }
            val now = clock.nowEpochMillis()
            try {
                leaf.checkValidity(Date(now))
            } catch (error: CertificateExpiredException) {
                throw SecException(SecErrorCode.CERT_EXPIRED, "leaf expired", error)
            } catch (error: CertificateNotYetValidException) {
                throw SecException(SecErrorCode.CERT_INVALID, "leaf not yet valid", error)
            }
            chain.drop(1).forEach { issuer ->
                try {
                    issuer.checkValidity(Date(now))
                } catch (error: Exception) {
                    throw SecException(SecErrorCode.CERT_INVALID, "issuer invalid", error)
                }
            }
            try {
                keys.importCertificateChain(config.keyAlias, chainDer)
            } catch (error: Exception) {
                throw SecException(SecErrorCode.KEY_UNAVAILABLE, "chain import failed", error)
            }
            val nextState = SecStateMachine.transition(identity.meta.state, SecEvent.CERT_IMPORTED)
            val meta = identity.meta.copy(
                deviceId = identity.meta.deviceId ?: deviceIdProvider(),
                certSn = leaf.serialNumber.toString(16).uppercase(),
                subject = leaf.subjectX500Principal.name,
                notBeforeEpochMillis = leaf.notBefore.time,
                notAfterEpochMillis = leaf.notAfter.time,
                state = nextState,
                lastReasonCode = SecErrorCode.OK.code,
                updatedAtEpochMillis = now,
            )
            metaStore.write(meta)
            recordAudit(null, AuditOperation.IMPORT_CERTIFICATE, AuditOutcome.OK, SecErrorCode.OK, startedAt)
            logger.event("provision.certificate_imported", "state" to nextState.name)
            return DeviceCertificateInfo(
                deviceId = meta.deviceId,
                subject = meta.subject,
                certSn = meta.certSn,
                notBeforeEpochMillis = meta.notBeforeEpochMillis,
                notAfterEpochMillis = meta.notAfterEpochMillis,
                fingerprintSha256 = CertificateChainCodec.fingerprintSha256Hex(leaf),
                state = nextState,
            )
        } catch (error: SecException) {
            recordAudit(null, AuditOperation.IMPORT_CERTIFICATE, AuditOutcome.FAILED, error.error, startedAt)
            logger.event("provision.certificate_failed", "error" to error.error.name)
            throw error
        }
    }

    /** Read-only row for the content provider; the provider permission is the access gate. */
    suspend fun providerSnapshot(): ProviderSnapshot {
        val identity = loadIdentity()
        return ProviderSnapshot(
            state = identity.meta.state.code,
            deviceId = identity.meta.deviceId,
            certSn = identity.meta.certSn,
            notAfterEpochMillis = identity.meta.notAfterEpochMillis,
            lastReasonCode = identity.meta.lastReasonCode,
            updatedAtEpochMillis = identity.meta.updatedAtEpochMillis,
        )
    }

    private fun authorize(uid: Int, operation: AuditOperation, startedAt: Long): CallerDescriptor {
        val caller = runCatching { callerVerifier.describe(uid) }.getOrNull()
        if (!callerPolicy.isAllowed(caller)) {
            recordAudit(caller, operation, AuditOutcome.REJECTED, SecErrorCode.CALLER_REJECTED, startedAt)
            logger.event("caller.rejected", "operation" to operation.name, "uid" to uid.toString())
            throw SecException(SecErrorCode.CALLER_REJECTED, "caller rejected")
        }
        return requireNotNull(caller)
    }

    private suspend fun loadIdentity(): Identity {
        val stored = metaStore.read()
        val hasKey = runCatching { keys.exists(config.keyAlias) }.getOrDefault(false)
        val chain = if (hasKey) {
            runCatching { keys.certificateChainDer(config.keyAlias) }.getOrNull()
        } else {
            null
        }
        val certificate = chain?.firstOrNull()?.let { der ->
            runCatching { certificateParser(der) }.getOrNull()
        }
        val now = clock.nowEpochMillis()
        val state = when {
            !hasKey -> SecState.NOT_PROVISIONED
            certificate == null -> when {
                chain != null -> SecState.ERROR
                stored.state == SecState.BLOCKED -> SecState.BLOCKED
                stored.state == SecState.ERROR -> SecState.ERROR
                else -> SecState.PROVISIONING
            }

            stored.state == SecState.BLOCKED -> SecState.BLOCKED
            stored.state == SecState.PROVISIONING -> SecState.PROVISIONING
            stored.state == SecState.ERROR -> SecState.ISSUED_PENDING_CLOUD
            stored.state == SecState.NOT_PROVISIONED -> SecState.ISSUED_PENDING_CLOUD
            else -> SecStateMachine.derive(
                state = stored.state,
                notAfterEpochMillis = certificate.notAfter.time,
                nowEpochMillis = now,
                renewalWindowMillis = config.certificateRenewWindowMillis,
            )
        }
        val refreshed = stored.copy(
            deviceId = stored.deviceId ?: deviceIdProvider(),
            certSn = certificate?.serialNumber?.toString(16)?.uppercase(),
            subject = certificate?.subjectX500Principal?.name,
            notBeforeEpochMillis = certificate?.notBefore?.time ?: stored.notBeforeEpochMillis,
            notAfterEpochMillis = certificate?.notAfter?.time ?: stored.notAfterEpochMillis,
            state = state,
            lastReasonCode = if (state == SecState.BLOCKED &&
                certificate != null &&
                certificate.notAfter.time <= now
            ) {
                SecErrorCode.CERT_EXPIRED.code
            } else {
                stored.lastReasonCode
            },
            updatedAtEpochMillis = if (state != stored.state) now else stored.updatedAtEpochMillis,
        )
        if (refreshed != stored) {
            runCatching { metaStore.write(refreshed) }
                .onFailure { logger.event("meta.write_failed", "reason" to it.javaClass.simpleName) }
        }
        val level = runCatching { keys.securityLevel(config.keyAlias) }
            .getOrDefault(KeySecurityLevel.SOFTWARE)
        return Identity(
            meta = refreshed,
            certificate = certificate,
            fingerprintSha256 = certificate?.let { CertificateChainCodec.fingerprintSha256Hex(it) },
            securityLevel = level,
        )
    }

    private fun errorForState(state: SecState, meta: SecMeta): SecErrorCode = when (state) {
        SecState.NOT_PROVISIONED, SecState.PROVISIONING -> SecErrorCode.NOT_PROVISIONED
        SecState.BLOCKED -> SecErrorCode.fromCode(meta.lastReasonCode) ?: SecErrorCode.CERT_INVALID
        SecState.ERROR -> SecErrorCode.KEY_UNAVAILABLE
        else -> SecErrorCode.CALLER_REJECTED
    }

    private suspend fun ensureCertificateValid(identity: Identity) {
        val certificate = identity.certificate
            ?: throw SecException(SecErrorCode.NOT_PROVISIONED, "certificate missing")
        val now = clock.nowEpochMillis()
        try {
            certificate.checkValidity(Date(now))
        } catch (error: CertificateExpiredException) {
            persistFailure(identity, SecErrorCode.CERT_EXPIRED)
            throw SecException(SecErrorCode.CERT_EXPIRED, "certificate expired", error)
        } catch (error: CertificateNotYetValidException) {
            persistFailure(identity, SecErrorCode.CERT_INVALID)
            throw SecException(SecErrorCode.CERT_INVALID, "certificate not yet valid", error)
        }
    }

    private suspend fun persistFailure(identity: Identity, error: SecErrorCode) {
        val current = identity.meta.state
        val event = when (error) {
            SecErrorCode.CERT_INVALID -> SecEvent.CERT_INVALID
            SecErrorCode.CERT_EXPIRED -> SecEvent.CERT_EXPIRED
            SecErrorCode.DEVICE_BLOCKED -> SecEvent.CLOUD_BLOCKED
            SecErrorCode.KEY_UNAVAILABLE -> SecEvent.KEY_UNAVAILABLE
            else -> null
        }
        val nextState = if (event != null && SecStateMachine.canTransition(current, event)) {
            SecStateMachine.transition(current, event)
        } else {
            current
        }
        val updated = identity.meta.copy(
            state = nextState,
            lastReasonCode = error.code,
            updatedAtEpochMillis = clock.nowEpochMillis(),
        )
        runCatching { metaStore.write(updated) }
            .onFailure { logger.event("meta.write_failed", "reason" to it.javaClass.simpleName) }
    }

    private fun recordAudit(
        caller: CallerDescriptor?,
        operation: AuditOperation,
        outcome: AuditOutcome,
        error: SecErrorCode,
        startedAt: Long,
    ) {
        val now = clock.nowEpochMillis()
        val entry = AuditEntry(
            timestampEpochMillis = now,
            uid = caller?.uid ?: -1,
            packageName = caller?.packageName,
            operation = operation,
            outcome = outcome,
            reasonCode = error.code,
            durationMillis = (now - startedAt).coerceAtLeast(0),
        )
        runCatching { audit.record(entry) }
            .onFailure { logger.event("audit.write_failed", "operation" to operation.name) }
    }
}
