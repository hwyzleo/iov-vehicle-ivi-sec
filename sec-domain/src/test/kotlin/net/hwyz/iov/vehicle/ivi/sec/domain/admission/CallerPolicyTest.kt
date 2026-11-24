package net.hwyz.iov.vehicle.ivi.sec.domain.admission

import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** US-005 / A-005: only whitelisted packages signed by the service key are admitted. */
class CallerPolicyTest {

    private val policy = CallerPolicy(setOf("net.hwyz.iov.vehicle.ivi.acc.demo"))

    @Test
    @DisplayName("Whitelisted package signed by the service passes")
    fun allowsWhitelistedSignedCaller() {
        assertTrue(policy.isAllowed(CallerDescriptor(10_100, "net.hwyz.iov.vehicle.ivi.acc.demo", "sig", true)))
    }

    @Test
    @DisplayName("Unlisted package, foreign signature, uid 0 and unresolved uid are rejected")
    fun rejectsOtherCallers() {
        assertFalse(policy.isAllowed(null))
        assertFalse(policy.isAllowed(CallerDescriptor(10_101, "com.example.evil", "sig", true)))
        assertFalse(policy.isAllowed(CallerDescriptor(10_100, "net.hwyz.iov.vehicle.ivi.acc.demo", "other", false)))
        assertFalse(policy.isAllowed(CallerDescriptor(0, "net.hwyz.iov.vehicle.ivi.acc.demo", "sig", true)))
        assertFalse(policy.isAllowed(CallerDescriptor(10_100, null, null, true)))
    }
}
