package net.hwyz.iov.vehicle.ivi.sec.domain.state

import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** IVI-SEC-SPEC §6.3 state machine and certificate expiry derivation. */
class SecStateMachineTest {

    @Test
    @DisplayName("Every documented transition is accepted")
    fun acceptsDocumentedTransitions() {
        val expected = mapOf(
            (SecState.NOT_PROVISIONED to SecEvent.KEY_GENERATED) to SecState.PROVISIONING,
            (SecState.PROVISIONING to SecEvent.CERT_IMPORTED) to SecState.ISSUED_PENDING_CLOUD,
            (SecState.ISSUED_PENDING_CLOUD to SecEvent.FIRST_TOKEN_ISSUED) to SecState.ACTIVE,
            (SecState.ACTIVE to SecEvent.RENEWAL_DUE) to SecState.RENEW_DUE,
            (SecState.RENEW_DUE to SecEvent.RENEWAL_COMPLETED) to SecState.ACTIVE,
            (SecState.ACTIVE to SecEvent.CLOUD_BLOCKED) to SecState.BLOCKED,
            (SecState.ISSUED_PENDING_CLOUD to SecEvent.CLOUD_BLOCKED) to SecState.BLOCKED,
            (SecState.ACTIVE to SecEvent.CERT_EXPIRED) to SecState.BLOCKED,
            (SecState.BLOCKED to SecEvent.REOPEN_REQUESTED) to SecState.PROVISIONING,
            (SecState.ACTIVE to SecEvent.KEY_UNAVAILABLE) to SecState.ERROR,
            (SecState.ERROR to SecEvent.KEY_REGENERATED) to SecState.PROVISIONING,
        )
        expected.forEach { (input, output) ->
            val (state, event) = input
            assertTrue(SecStateMachine.canTransition(state, event), "$state + $event must be allowed")
            assertEquals(output, SecStateMachine.transition(state, event))
        }
    }

    @Test
    @DisplayName("Unknown transitions are rejected, never silently accepted")
    fun rejectsUnknownTransitions() {
        assertFalse(SecStateMachine.canTransition(SecState.NOT_PROVISIONED, SecEvent.FIRST_TOKEN_ISSUED))
        assertFailsWith<IllegalStateException> {
            SecStateMachine.transition(SecState.NOT_PROVISIONED, SecEvent.RENEWAL_DUE)
        }
        assertFailsWith<IllegalStateException> {
            SecStateMachine.transition(SecState.BLOCKED, SecEvent.CERT_IMPORTED)
        }
    }

    @Test
    @DisplayName("An expired certificate blocks; a short remaining lifetime marks RENEW_DUE")
    fun derivesFromCertificateValidity() {
        val now = 1_700_000_000_000L
        val sevenDays = 7L * 24 * 60 * 60 * 1_000

        assertEquals(
            SecState.BLOCKED,
            SecStateMachine.derive(SecState.ACTIVE, notAfterEpochMillis = now - 1, nowEpochMillis = now, sevenDays),
        )
        assertEquals(
            SecState.RENEW_DUE,
            SecStateMachine.derive(SecState.ACTIVE, notAfterEpochMillis = now + sevenDays, nowEpochMillis = now, sevenDays),
        )
        assertEquals(
            SecState.ACTIVE,
            SecStateMachine.derive(SecState.ACTIVE, notAfterEpochMillis = now + sevenDays + 1, nowEpochMillis = now, sevenDays),
        )
        assertEquals(
            SecState.ISSUED_PENDING_CLOUD,
            SecStateMachine.derive(SecState.ISSUED_PENDING_CLOUD, notAfterEpochMillis = now + sevenDays, nowEpochMillis = now, sevenDays),
        )
        assertEquals(
            SecState.NOT_PROVISIONED,
            SecStateMachine.derive(SecState.NOT_PROVISIONED, notAfterEpochMillis = now - 1, nowEpochMillis = now, sevenDays),
        )
    }
}
