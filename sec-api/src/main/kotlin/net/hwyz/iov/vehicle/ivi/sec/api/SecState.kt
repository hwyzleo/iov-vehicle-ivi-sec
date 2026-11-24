package net.hwyz.iov.vehicle.ivi.sec.api

/**
 * Security state exposed to callers (IVI-SEC-SPEC §4.3).
 *
 * Values are part of the cross-application contract and must not be renumbered.
 */
object SecState {
    const val NOT_PROVISIONED = 0
    const val PROVISIONING = 1
    const val ISSUED_PENDING_CLOUD = 2
    const val ACTIVE = 3
    const val RENEW_DUE = 4
    const val BLOCKED = 5
    const val ERROR = 6

    fun nameOf(state: Int): String = when (state) {
        NOT_PROVISIONED -> "NOT_PROVISIONED"
        PROVISIONING -> "PROVISIONING"
        ISSUED_PENDING_CLOUD -> "ISSUED_PENDING_CLOUD"
        ACTIVE -> "ACTIVE"
        RENEW_DUE -> "RENEW_DUE"
        BLOCKED -> "BLOCKED"
        ERROR -> "ERROR"
        else -> "UNKNOWN"
    }

    /** True when the device identity is fully usable (certificate valid and cloud-confirmed). */
    fun isUsable(state: Int): Boolean = state == ACTIVE || state == RENEW_DUE

    /** True when the service may sign and request a device token (cloud confirmation still pending). */
    fun isTokenEligible(state: Int): Boolean =
        state == ISSUED_PENDING_CLOUD || state == ACTIVE || state == RENEW_DUE
}
