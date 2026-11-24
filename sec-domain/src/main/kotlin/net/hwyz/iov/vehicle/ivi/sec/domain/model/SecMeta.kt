package net.hwyz.iov.vehicle.ivi.sec.domain.model

/**
 * Non-secret security metadata persisted in DataStore (IVI-SEC-SPEC §6).
 *
 * Absent numeric values are represented by 0 so the record round-trips through preferences without
 * nullable primitives.
 */
data class SecMeta(
    val deviceId: String? = null,
    val certSn: String? = null,
    val subject: String? = null,
    val notBeforeEpochMillis: Long = 0,
    val notAfterEpochMillis: Long = 0,
    val state: SecState = SecState.NOT_PROVISIONED,
    val lastReasonCode: Int = 0,
    val lastIssuedAtEpochMillis: Long = 0,
    val updatedAtEpochMillis: Long = 0,
) {
    val hasCertificate: Boolean get() = notAfterEpochMillis > 0
}
