package net.hwyz.iov.vehicle.ivi.sec.domain.admission

import net.hwyz.iov.vehicle.ivi.sec.domain.clock.Clock

/**
 * Sliding window rate limiter (IVI-SEC-SPEC §7).
 *
 * signNonce is limited per caller; token issuance is limited for the whole device so the local
 * budget never exceeds the cloud quota of 12/minute.
 */
class RateLimiter(
    private val clock: Clock = Clock.System,
    private val signPerCallerPerMinute: Int = 30,
    private val tokenPerDevicePerMinute: Int = 12,
    private val windowMillis: Long = 60_000L,
) {
    init {
        require(signPerCallerPerMinute > 0) { "sign limit must be positive" }
        require(tokenPerDevicePerMinute > 0) { "token limit must be positive" }
        require(windowMillis > 0) { "window must be positive" }
    }

    private val lock = Any()
    private val signWindows = HashMap<String, ArrayDeque<Long>>()
    private val tokenWindow = ArrayDeque<Long>()

    fun tryAcquireSign(callerKey: String): Boolean = synchronized(lock) {
        acquire(signWindows.getOrPut(callerKey) { ArrayDeque() }, signPerCallerPerMinute)
    }

    fun tryAcquireToken(): Boolean = synchronized(lock) {
        acquire(tokenWindow, tokenPerDevicePerMinute)
    }

    private fun acquire(window: ArrayDeque<Long>, limit: Int): Boolean {
        val now = clock.nowEpochMillis()
        while (window.isNotEmpty() && now - window.first() >= windowMillis) {
            window.removeFirst()
        }
        if (window.size >= limit) return false
        window.addLast(now)
        return true
    }
}
