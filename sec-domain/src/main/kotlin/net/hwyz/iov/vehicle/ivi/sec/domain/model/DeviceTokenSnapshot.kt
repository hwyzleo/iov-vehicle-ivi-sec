package net.hwyz.iov.vehicle.ivi.sec.domain.model

/** In-memory device token (IVI-SEC-SPEC §6: never persisted, never logged). */
data class DeviceTokenSnapshot(
    val accessToken: String,
    val scopes: List<String>,
    val issuedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
) {
    fun remainingMillis(nowEpochMillis: Long): Long = expiresAtEpochMillis - nowEpochMillis
}
