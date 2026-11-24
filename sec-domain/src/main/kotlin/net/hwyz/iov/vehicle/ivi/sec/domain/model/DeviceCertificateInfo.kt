package net.hwyz.iov.vehicle.ivi.sec.domain.model

/** Non-secret certificate view returned to callers (IVI-SEC-SPEC §4.2). */
data class DeviceCertificateInfo(
    val deviceId: String?,
    val subject: String?,
    val certSn: String?,
    val notBeforeEpochMillis: Long,
    val notAfterEpochMillis: Long,
    val fingerprintSha256: String?,
    val state: SecState,
)
