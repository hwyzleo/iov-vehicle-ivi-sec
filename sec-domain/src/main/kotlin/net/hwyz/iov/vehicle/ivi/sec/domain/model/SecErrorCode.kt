package net.hwyz.iov.vehicle.ivi.sec.domain.model

/**
 * Local error taxonomy published to callers (IVI-SEC-SPEC §4.3).
 *
 * Codes are stable contract values; the service must not renumber them.
 */
enum class SecErrorCode(val code: Int, val retryable: Boolean) {
    OK(0, false),
    NOT_PROVISIONED(1, false),
    CALLER_REJECTED(2, false),
    INVALID_ARGUMENT(3, false),
    KEY_UNAVAILABLE(4, true),
    CERT_INVALID(5, false),
    CERT_EXPIRED(6, false),
    TOKEN_UNAVAILABLE(7, false),
    RATE_LIMITED(8, true),
    DEPENDENCY_UNAVAILABLE(9, true),
    DEVICE_BLOCKED(10, false),
    SESSION_CONFLICT(11, false),
    ;

    companion object {
        fun fromCode(code: Int): SecErrorCode? = entries.firstOrNull { it.code == code }
    }
}
