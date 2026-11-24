package net.hwyz.iov.vehicle.ivi.sec.domain.token

import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode

/**
 * Maps SEC-CIAM business codes and HTTP outcomes to local error codes (IVI-SEC-SPEC §4.5).
 *
 * The mapping is frozen: retry guidance never depends on a message string.
 */
object CloudErrorMapper {

    const val SUCCESS_CODE = "000000"

    private val SUCCESS_CODES = setOf("000000", "0", "200")

    fun isSuccess(code: String?): Boolean = code == null || code in SUCCESS_CODES

    fun mapBusinessCode(code: String?): SecErrorCode = when (code) {
        "701325" -> SecErrorCode.CERT_INVALID
        "701326" -> SecErrorCode.DEPENDENCY_UNAVAILABLE
        "701327" -> SecErrorCode.DEVICE_BLOCKED
        "701328" -> SecErrorCode.DEVICE_BLOCKED
        "701329" -> SecErrorCode.SESSION_CONFLICT
        "701330" -> SecErrorCode.TOKEN_UNAVAILABLE
        "701331" -> SecErrorCode.TOKEN_UNAVAILABLE
        else -> SecErrorCode.TOKEN_UNAVAILABLE
    }

    /** Returns null for a 2xx status; transport failures are classified by the client itself. */
    fun mapHttpStatus(status: Int): SecErrorCode? = when {
        status in 200..299 -> null
        status == 408 || status == 429 -> SecErrorCode.DEPENDENCY_UNAVAILABLE
        status >= 500 -> SecErrorCode.DEPENDENCY_UNAVAILABLE
        status == 401 || status == 403 -> SecErrorCode.TOKEN_UNAVAILABLE
        else -> SecErrorCode.TOKEN_UNAVAILABLE
    }
}
