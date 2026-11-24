package net.hwyz.iov.vehicle.ivi.sec.api

/**
 * Stable local error codes returned through [android.os.ServiceSpecificException] (§4.3).
 *
 * Values are part of the cross-application contract and must not be renumbered.
 */
object SecError {
    const val OK = 0
    const val NOT_PROVISIONED = 1
    const val CALLER_REJECTED = 2
    const val INVALID_ARGUMENT = 3
    const val KEY_UNAVAILABLE = 4
    const val CERT_INVALID = 5
    const val CERT_EXPIRED = 6
    const val TOKEN_UNAVAILABLE = 7
    const val RATE_LIMITED = 8
    const val DEPENDENCY_UNAVAILABLE = 9
    const val DEVICE_BLOCKED = 10
    const val SESSION_CONFLICT = 11

    fun nameOf(code: Int): String = when (code) {
        OK -> "OK"
        NOT_PROVISIONED -> "NOT_PROVISIONED"
        CALLER_REJECTED -> "CALLER_REJECTED"
        INVALID_ARGUMENT -> "INVALID_ARGUMENT"
        KEY_UNAVAILABLE -> "KEY_UNAVAILABLE"
        CERT_INVALID -> "CERT_INVALID"
        CERT_EXPIRED -> "CERT_EXPIRED"
        TOKEN_UNAVAILABLE -> "TOKEN_UNAVAILABLE"
        RATE_LIMITED -> "RATE_LIMITED"
        DEPENDENCY_UNAVAILABLE -> "DEPENDENCY_UNAVAILABLE"
        DEVICE_BLOCKED -> "DEVICE_BLOCKED"
        SESSION_CONFLICT -> "SESSION_CONFLICT"
        else -> "UNKNOWN"
    }

    /** Retry guidance published to callers: only these codes are worth a bounded retry. */
    fun isRetryable(code: Int): Boolean = when (code) {
        KEY_UNAVAILABLE, RATE_LIMITED, DEPENDENCY_UNAVAILABLE -> true
        else -> false
    }

    /**
     * Binder failure wire format. Android has no public `ServiceSpecificException`, so a stable,
     * parseable message is used on top of the public [IllegalStateException] /
     * [SecurityException] channel. Format: `IVI_SEC:<code>:<NAME>`.
     */
    fun wireMessage(code: Int): String = "$WIRE_PREFIX$code:${nameOf(code)}"

    fun codeOfWireMessage(message: String?): Int? {
        val value = message?.takeIf { it.startsWith(WIRE_PREFIX) } ?: return null
        return value.substring(WIRE_PREFIX.length).substringBefore(':').toIntOrNull()
    }

    const val WIRE_PREFIX = "IVI_SEC:"
}
