package net.hwyz.iov.vehicle.ivi.sec.domain.state

import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState

/** Events that move the security state machine (IVI-SEC-SPEC §6.3). */
enum class SecEvent {
    KEY_GENERATED,
    KEY_REGENERATED,
    CERT_IMPORTED,
    FIRST_TOKEN_ISSUED,
    RENEWAL_DUE,
    RENEWAL_COMPLETED,
    CLOUD_BLOCKED,
    CERT_INVALID,
    CERT_EXPIRED,
    KEY_UNAVAILABLE,
    REOPEN_REQUESTED,
}

/**
 * Stateless security state machine.
 *
 * The table is intentionally small and explicit: any unknown transition is rejected instead of
 * silently keeping the current state.
 */
object SecStateMachine {

    private val transitions: Map<Pair<SecState, SecEvent>, SecState> = mapOf(
        (SecState.NOT_PROVISIONED to SecEvent.KEY_GENERATED) to SecState.PROVISIONING,

        (SecState.PROVISIONING to SecEvent.KEY_REGENERATED) to SecState.PROVISIONING,
        (SecState.PROVISIONING to SecEvent.CERT_IMPORTED) to SecState.ISSUED_PENDING_CLOUD,
        (SecState.PROVISIONING to SecEvent.REOPEN_REQUESTED) to SecState.PROVISIONING,

        (SecState.ISSUED_PENDING_CLOUD to SecEvent.FIRST_TOKEN_ISSUED) to SecState.ACTIVE,
        (SecState.ISSUED_PENDING_CLOUD to SecEvent.CLOUD_BLOCKED) to SecState.BLOCKED,
        (SecState.ISSUED_PENDING_CLOUD to SecEvent.CERT_INVALID) to SecState.BLOCKED,
        (SecState.ISSUED_PENDING_CLOUD to SecEvent.CERT_EXPIRED) to SecState.BLOCKED,
        (SecState.ISSUED_PENDING_CLOUD to SecEvent.KEY_UNAVAILABLE) to SecState.ERROR,
        (SecState.ISSUED_PENDING_CLOUD to SecEvent.REOPEN_REQUESTED) to SecState.PROVISIONING,

        (SecState.ACTIVE to SecEvent.RENEWAL_DUE) to SecState.RENEW_DUE,
        (SecState.ACTIVE to SecEvent.CLOUD_BLOCKED) to SecState.BLOCKED,
        (SecState.ACTIVE to SecEvent.CERT_INVALID) to SecState.BLOCKED,
        (SecState.ACTIVE to SecEvent.CERT_EXPIRED) to SecState.BLOCKED,
        (SecState.ACTIVE to SecEvent.KEY_UNAVAILABLE) to SecState.ERROR,
        (SecState.ACTIVE to SecEvent.REOPEN_REQUESTED) to SecState.PROVISIONING,

        (SecState.RENEW_DUE to SecEvent.RENEWAL_COMPLETED) to SecState.ACTIVE,
        (SecState.RENEW_DUE to SecEvent.CLOUD_BLOCKED) to SecState.BLOCKED,
        (SecState.RENEW_DUE to SecEvent.CERT_INVALID) to SecState.BLOCKED,
        (SecState.RENEW_DUE to SecEvent.CERT_EXPIRED) to SecState.BLOCKED,
        (SecState.RENEW_DUE to SecEvent.KEY_UNAVAILABLE) to SecState.ERROR,
        (SecState.RENEW_DUE to SecEvent.REOPEN_REQUESTED) to SecState.PROVISIONING,

        (SecState.BLOCKED to SecEvent.REOPEN_REQUESTED) to SecState.PROVISIONING,
        (SecState.BLOCKED to SecEvent.KEY_REGENERATED) to SecState.PROVISIONING,

        (SecState.ERROR to SecEvent.KEY_REGENERATED) to SecState.PROVISIONING,
        (SecState.ERROR to SecEvent.REOPEN_REQUESTED) to SecState.PROVISIONING,
    )

    fun canTransition(current: SecState, event: SecEvent): Boolean =
        transitions.containsKey(current to event)

    fun transition(current: SecState, event: SecEvent): SecState =
        transitions[current to event]
            ?: throw IllegalStateException("illegal transition $current + $event")

    /**
     * Applies certificate expiry rules without consuming an event:
     * an expired certificate blocks, and a certificate inside the renewal window marks RENEW_DUE.
     * Cloud-confirmation states are not downgraded to RENEW_DUE.
     */
    fun derive(
        state: SecState,
        notAfterEpochMillis: Long,
        nowEpochMillis: Long,
        renewalWindowMillis: Long,
    ): SecState {
        if (state != SecState.ACTIVE && state != SecState.RENEW_DUE && state != SecState.ISSUED_PENDING_CLOUD) {
            return state
        }
        if (notAfterEpochMillis in 1..nowEpochMillis) return SecState.BLOCKED
        if (state == SecState.ISSUED_PENDING_CLOUD) return state
        if (notAfterEpochMillis == 0L) return state
        if (notAfterEpochMillis - nowEpochMillis <= renewalWindowMillis) return SecState.RENEW_DUE
        return state
    }
}
