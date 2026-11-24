package net.hwyz.iov.vehicle.ivi.sec.domain.admission

import net.hwyz.iov.vehicle.ivi.sec.domain.support.FakeClock
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** US-005 / A-006: local sliding window limits (30 sign/min per caller, 12 tokens/min per device). */
class RateLimiterTest {

    @Test
    @DisplayName("The 31st sign in one window is limited; other callers are unaffected")
    fun limitsPerCaller() {
        val clock = FakeClock()
        val limiter = RateLimiter(clock, signPerCallerPerMinute = 30, tokenPerDevicePerMinute = 12)
        repeat(30) { assertTrue(limiter.tryAcquireSign("caller-a")) }
        assertFalse(limiter.tryAcquireSign("caller-a"))
        assertTrue(limiter.tryAcquireSign("caller-b"))
    }

    @Test
    @DisplayName("The window slides: a permit is available again after 60 seconds")
    fun windowSlides() {
        val clock = FakeClock()
        val limiter = RateLimiter(clock, signPerCallerPerMinute = 2, tokenPerDevicePerMinute = 12)
        assertTrue(limiter.tryAcquireSign("caller-a"))
        assertTrue(limiter.tryAcquireSign("caller-a"))
        assertFalse(limiter.tryAcquireSign("caller-a"))
        clock.now += 60_000
        assertTrue(limiter.tryAcquireSign("caller-a"))
    }

    @Test
    @DisplayName("Token issuance is limited for the whole device")
    fun limitsTokenIssuance() {
        val clock = FakeClock()
        val limiter = RateLimiter(clock, signPerCallerPerMinute = 30, tokenPerDevicePerMinute = 12)
        repeat(12) { assertTrue(limiter.tryAcquireToken()) }
        assertFalse(limiter.tryAcquireToken())
        clock.now += 59_999
        assertFalse(limiter.tryAcquireToken())
        clock.now += 1
        assertTrue(limiter.tryAcquireToken())
    }
}
