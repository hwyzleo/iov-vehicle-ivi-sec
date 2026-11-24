package net.hwyz.iov.vehicle.ivi.sec.domain.token

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.hwyz.iov.vehicle.ivi.sec.domain.SecException
import net.hwyz.iov.vehicle.ivi.sec.domain.clock.Clock
import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceTokenSnapshot
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceTokenPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.domain.port.NoOpDiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome

/** Token lifecycle timings (IVI-SEC-SPEC D-010, C-004). */
data class TokenConfig(
    /** Re-prove when less than this remains; the cloud token TTL is 15 minutes. */
    val renewWindowMillis: Long = 5 * 60_000L,
    /** Used when the cloud omits expires_in; never extends a real TTL. */
    val fallbackTtlMillis: Long = 15 * 60_000L,
    /** 701329 is retried once after dropping the cache (IVI-SEC-SPEC §7.4). */
    val conflictRetryCount: Int = 1,
)

/** One token request result; failures are classified and never fabricated. */
sealed interface DeviceTokenResult {
    data class Issued(val token: DeviceTokenSnapshot) : DeviceTokenResult

    data class Failed(
        val error: SecErrorCode,
        val cloudCode: String? = null,
        val message: String? = null,
    ) : DeviceTokenResult
}

/**
 * Owns the in-memory device token (IVI-SEC-SPEC D-004 / D-010).
 *
 * - one cloud issuance in flight per process (single flight);
 * - cache hit only while more than the renewal window remains;
 * - 701329 drops the cache and retries exactly once;
 * - failed results are not cached.
 */
class DeviceTokenCoordinator(
    private val port: DeviceTokenPort,
    private val proofGenerator: ProofGenerator,
    private val scopes: DeviceScopes,
    private val config: TokenConfig = TokenConfig(),
    private val clock: Clock = Clock.System,
    private val logger: DiagnosticsLogger = NoOpDiagnosticsLogger,
    /** Issuance budget (12/minute per device); cache hits never consume it. */
    private val issuePermit: () -> Boolean = { true },
) {
    private val mutex = Mutex()

    @Volatile
    private var cached: DeviceTokenSnapshot? = null

    suspend fun token(requestedScopes: List<String>): DeviceTokenResult {
        val normalized = try {
            scopes.normalize(requestedScopes)
        } catch (error: SecException) {
            return DeviceTokenResult.Failed(error.error, message = error.reason)
        }
        return mutex.withLock { tokenLocked(normalized) }
    }

    suspend fun invalidate() {
        mutex.withLock { cached = null }
        logger.event("token.invalidated")
    }

    fun cachedTokenOrNull(): DeviceTokenSnapshot? = cached

    private suspend fun tokenLocked(requested: List<String>): DeviceTokenResult {
        val now = clock.nowEpochMillis()
        cached?.let { token ->
            if (token.remainingMillis(now) > config.renewWindowMillis) {
                logger.event("token.cache_hit", "remaining_ms" to token.remainingMillis(now).toString())
                return DeviceTokenResult.Issued(token)
            }
        }
        var attempts = 0
        while (true) {
            val result = issue(requested)
            if (result is DeviceTokenResult.Failed &&
                result.error == SecErrorCode.SESSION_CONFLICT &&
                attempts < config.conflictRetryCount
            ) {
                attempts++
                cached = null
                logger.event("token.conflict_retry", "attempt" to attempts.toString())
                continue
            }
            return result
        }
    }

    private suspend fun issue(requested: List<String>): DeviceTokenResult {
        if (!issuePermit()) {
            logger.event("token.rate_limited")
            return DeviceTokenResult.Failed(SecErrorCode.RATE_LIMITED, message = "token limit")
        }
        val proof = try {
            proofGenerator.generate()
        } catch (error: Exception) {
            logger.event("token.proof_failed", "reason" to error.javaClass.simpleName)
            return DeviceTokenResult.Failed(SecErrorCode.KEY_UNAVAILABLE, message = "proof-unavailable")
        }
        val outcome = try {
            port.request(proof, requested)
        } catch (error: Exception) {
            logger.event("token.request_failed", "reason" to error.javaClass.simpleName)
            return DeviceTokenResult.Failed(
                SecErrorCode.DEPENDENCY_UNAVAILABLE,
                message = "transport",
            )
        }
        return when (outcome) {
            is TokenIssueOutcome.Issued -> {
                val issuedAt = clock.nowEpochMillis()
                val ttlMillis = if (outcome.expiresInSeconds > 0) {
                    outcome.expiresInSeconds * 1_000L
                } else {
                    config.fallbackTtlMillis
                }
                val token = DeviceTokenSnapshot(
                    accessToken = outcome.accessToken,
                    scopes = requested,
                    issuedAtEpochMillis = issuedAt,
                    expiresAtEpochMillis = issuedAt + ttlMillis,
                )
                cached = token
                logger.event(
                    "token.issued",
                    "ttl_seconds" to (ttlMillis / 1_000L).toString(),
                    "scope_count" to requested.size.toString(),
                )
                DeviceTokenResult.Issued(token)
            }

            is TokenIssueOutcome.Failed -> {
                cached = null
                logger.event(
                    "token.rejected",
                    "error" to outcome.error.name,
                    "cloud_code" to (outcome.cloudCode ?: "-"),
                )
                DeviceTokenResult.Failed(outcome.error, outcome.cloudCode, outcome.message)
            }
        }
    }
}
