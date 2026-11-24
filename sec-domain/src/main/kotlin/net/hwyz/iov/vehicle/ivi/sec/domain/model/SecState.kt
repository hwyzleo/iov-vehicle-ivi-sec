package net.hwyz.iov.vehicle.ivi.sec.domain.model

/** Security state machine states (IVI-SEC-SPEC §6.3). Codes are the published contract values. */
enum class SecState(val code: Int) {
    NOT_PROVISIONED(0),
    PROVISIONING(1),
    ISSUED_PENDING_CLOUD(2),
    ACTIVE(3),
    RENEW_DUE(4),
    BLOCKED(5),
    ERROR(6),
    ;

    /** Fully usable device identity: certificate valid and cloud confirmed. */
    val usable: Boolean get() = this == ACTIVE || this == RENEW_DUE

    /** Signing and token requests are allowed; cloud confirmation may still be pending. */
    val tokenEligible: Boolean
        get() = this == ISSUED_PENDING_CLOUD || this == ACTIVE || this == RENEW_DUE

    companion object {
        fun fromCode(code: Int): SecState? = entries.firstOrNull { it.code == code }
    }
}
