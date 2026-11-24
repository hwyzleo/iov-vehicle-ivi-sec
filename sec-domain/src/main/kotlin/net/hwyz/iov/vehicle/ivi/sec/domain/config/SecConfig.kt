package net.hwyz.iov.vehicle.ivi.sec.domain.config

import net.hwyz.iov.vehicle.ivi.sec.domain.audit.AuditRingBuffer
import net.hwyz.iov.vehicle.ivi.sec.domain.crypto.CsrProfile

/**
 * Static service configuration (IVI-SEC-SPEC §5, §7, §9).
 *
 * Values that belong to a deployment (base URL, client id, caller allowlist) are supplied by the app
 * module; this object holds the security policy defaults that are part of the design.
 */
data class SecConfig(
    val keyAlias: String = "ivi-sec-device-v1",
    val deviceScopes: List<String> = listOf("vehicle.activation", "vehicle.privacy.report"),
    val nonceMinLength: Int = NONCE_MIN_LENGTH,
    val nonceMaxLength: Int = NONCE_MAX_LENGTH,
    /** RENEW_DUE when the certificate expires inside this window (IVI-SEC-SPEC §6.3). */
    val certificateRenewWindowMillis: Long = 7L * 24 * 60 * 60 * 1_000,
    val signPerCallerPerMinute: Int = 30,
    val tokenPerDevicePerMinute: Int = 12,
    val rateWindowMillis: Long = 60_000L,
    val auditCapacity: Int = AuditRingBuffer.DEFAULT_CAPACITY,
    /** HSM/ECU UID used as CSR CN and SAN; supplied by deployment until a vendor source exists. */
    val hsmUid: String? = null,
    val csrOrganizationalUnit: String = CsrProfile.DEFAULT_ORGANIZATIONAL_UNIT,
    val csrOrganization: String = CsrProfile.DEFAULT_ORGANIZATION,
    val csrCountry: String = CsrProfile.DEFAULT_COUNTRY,
    val csrSanUriPrefix: String = CsrProfile.DEFAULT_SAN_URI_PREFIX,
) {
    init {
        require(keyAlias.isNotBlank()) { "key alias is blank" }
        require(deviceScopes.isNotEmpty()) { "device scope set is empty" }
        require(nonceMinLength > 0 && nonceMaxLength >= nonceMinLength) { "invalid nonce bounds" }
        require(certificateRenewWindowMillis > 0) { "invalid renewal window" }
        require(signPerCallerPerMinute > 0) { "invalid sign limit" }
        require(tokenPerDevicePerMinute > 0) { "invalid token limit" }
        require(rateWindowMillis > 0) { "invalid rate window" }
        require(auditCapacity > 0) { "invalid audit capacity" }
        require(hsmUid == null || hsmUid.isNotBlank()) { "hsm uid is blank" }
        require(csrOrganizationalUnit.isNotBlank()) { "CSR OU is blank" }
        require(csrOrganization.isNotBlank()) { "CSR O is blank" }
        require(csrCountry.isNotBlank()) { "CSR C is blank" }
        require(csrSanUriPrefix.isNotBlank()) { "CSR SAN prefix is blank" }
    }

    companion object {
        const val NONCE_MIN_LENGTH = 16
        const val NONCE_MAX_LENGTH = 128
    }
}
