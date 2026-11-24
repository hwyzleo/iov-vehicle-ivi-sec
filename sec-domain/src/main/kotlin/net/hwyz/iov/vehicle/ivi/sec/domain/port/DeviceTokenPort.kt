package net.hwyz.iov.vehicle.ivi.sec.domain.port

import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceProof
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode

/** Outcome of one device identity grant request (IVI-SEC-SPEC §4.5). */
sealed interface TokenIssueOutcome {
    data class Issued(
        val accessToken: String,
        val expiresInSeconds: Long,
        val scope: String?,
    ) : TokenIssueOutcome

    /**
     * [cloudCode] is the IAM business code, kept for diagnostics only. A failed result is never
     * cached: the next request proves the device again.
     */
    data class Failed(
        val error: SecErrorCode,
        val cloudCode: String? = null,
        val message: String? = null,
    ) : TokenIssueOutcome
}

/** SEC-CIAM device identity grant client (IVI-SEC-SPEC D-004). */
interface DeviceTokenPort {
    suspend fun request(proof: DeviceProof, scopes: List<String>): TokenIssueOutcome
}
