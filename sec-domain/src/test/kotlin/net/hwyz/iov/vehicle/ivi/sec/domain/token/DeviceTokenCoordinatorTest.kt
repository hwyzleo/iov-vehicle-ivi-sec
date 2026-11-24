package net.hwyz.iov.vehicle.ivi.sec.domain.token

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome
import net.hwyz.iov.vehicle.ivi.sec.domain.support.FakeClock
import net.hwyz.iov.vehicle.ivi.sec.domain.support.FakeDeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.support.FakeTokenPort
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** US-004 / A-003 / A-007 / A-010 / A-012: token lifecycle and single flight. */
class DeviceTokenCoordinatorTest {

    private val clock = FakeClock()
    private val port = FakeTokenPort()
    private val keys = FakeDeviceKeyPort().apply { keyPresent = true }
    private val scopes = DeviceScopes(listOf("vehicle.activation", "vehicle.privacy.report"))

    private fun coordinator(
        tokenConfig: TokenConfig = TokenConfig(),
        issuePermit: () -> Boolean = { true },
    ) = DeviceTokenCoordinator(
        port = port,
        proofGenerator = KeystoreProofGenerator(keys, "alias", "SN-TEST-001"),
        scopes = scopes,
        config = tokenConfig,
        clock = clock,
        issuePermit = issuePermit,
    )

    @Test
    @DisplayName("A valid cached token is returned without another cloud call")
    fun cacheHitDoesNotIssue() = runBlocking {
        val coordinator = coordinator()
        val first = assertIs<DeviceTokenResult.Issued>(coordinator.token(emptyList()))
        clock.now += 60_000
        val second = assertIs<DeviceTokenResult.Issued>(coordinator.token(emptyList()))

        assertEquals(first.token.accessToken, second.token.accessToken)
        assertEquals(1, port.calls.get())
        assertTrue(port.lastProof!!.nonceBase64.isNotEmpty())
        assertEquals(KeystoreProofGenerator.PROOF_TYPE, port.lastProof!!.proofType)
    }

    @Test
    @DisplayName("Inside the 5 minute renewal window the device proves again")
    fun renewsInsideWindow() = runBlocking {
        val coordinator = coordinator()
        coordinator.token(emptyList())
        clock.now += 600_001
        coordinator.token(emptyList())
        assertEquals(2, port.calls.get())
    }

    @Test
    @DisplayName("Fifty concurrent callers produce exactly one cloud issuance")
    fun singleFlight() = runBlocking {
        port.delayMillis = 50
        val coordinator = coordinator()
        val results = coroutineScope {
            (1..50).map {
                async(Dispatchers.Default) { coordinator.token(emptyList()) }
            }.awaitAll()
        }
        assertEquals(1, port.calls.get())
        assertTrue(results.all { it is DeviceTokenResult.Issued })
        val tokens = results.map { (it as DeviceTokenResult.Issued).token.accessToken }.toSet()
        assertEquals(1, tokens.size)
    }

    @Test
    @DisplayName("701329 drops the cache and retries exactly once")
    fun retriesSessionConflictOnce() = runBlocking {
        val coordinator = coordinator()
        port.enqueue(TokenIssueOutcome.Failed(SecErrorCode.SESSION_CONFLICT, "701329"))
        port.enqueue(TokenIssueOutcome.Failed(SecErrorCode.SESSION_CONFLICT, "701329"))

        val result = assertIs<DeviceTokenResult.Failed>(coordinator.token(emptyList()))
        assertEquals(SecErrorCode.SESSION_CONFLICT, result.error)
        assertEquals(2, port.calls.get())
    }

    @Test
    @DisplayName("A failed issuance is not cached")
    fun failureIsNotCached() = runBlocking {
        val coordinator = coordinator()
        port.enqueue(TokenIssueOutcome.Failed(SecErrorCode.DEPENDENCY_UNAVAILABLE, "http-503"))
        assertIs<DeviceTokenResult.Failed>(coordinator.token(emptyList()))
        assertIs<DeviceTokenResult.Issued>(coordinator.token(emptyList()))
        assertEquals(2, port.calls.get())
    }

    @Test
    @DisplayName("Account level scopes are rejected before any cloud call")
    fun rejectsInvalidScopeWithoutCall() = runBlocking {
        val coordinator = coordinator()
        val result = assertIs<DeviceTokenResult.Failed>(coordinator.token(listOf("user.profile")))
        assertEquals(SecErrorCode.INVALID_ARGUMENT, result.error)
        assertEquals(0, port.calls.get())
    }

    @Test
    @DisplayName("The issuance permit gates cloud calls only, not cache hits")
    fun issuancePermitGatesOnlyRealIssuance() = runBlocking {
        var permits = 1
        val coordinator = coordinator(issuePermit = { permits-- > 0 })
        assertIs<DeviceTokenResult.Issued>(coordinator.token(emptyList()))
        assertIs<DeviceTokenResult.Issued>(coordinator.token(emptyList()))
        assertEquals(1, port.calls.get())

        coordinator.invalidate()
        val result = assertIs<DeviceTokenResult.Failed>(coordinator.token(emptyList()))
        assertEquals(SecErrorCode.RATE_LIMITED, result.error)
        assertEquals(1, port.calls.get())
    }

    @Test
    @DisplayName("Invalidate forces a fresh proof on the next request")
    fun invalidateForcesNewIssuance() = runBlocking {
        val coordinator = coordinator()
        coordinator.token(emptyList())
        coordinator.invalidate()
        coordinator.token(emptyList())
        assertEquals(2, port.calls.get())
    }

    @Test
    @DisplayName("A proof signing failure is reported as KEY_UNAVAILABLE without a cloud call")
    fun proofFailureFailsClosed() = runBlocking {
        keys.signFailure = IllegalStateException("keystore unavailable")
        val coordinator = coordinator()
        val result = assertIs<DeviceTokenResult.Failed>(coordinator.token(emptyList()))
        assertEquals(SecErrorCode.KEY_UNAVAILABLE, result.error)
        assertEquals(0, port.calls.get())
    }

    @Test
    @DisplayName("Two proofs use different nonces")
    fun noncesAreFresh() = runBlocking {
        val coordinator = coordinator()
        coordinator.token(emptyList())
        val firstNonce = port.lastProof!!.nonceBase64
        coordinator.invalidate()
        coordinator.token(emptyList())
        assertTrue(firstNonce != port.lastProof!!.nonceBase64)
    }
}
