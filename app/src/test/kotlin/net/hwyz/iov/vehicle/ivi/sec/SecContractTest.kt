package net.hwyz.iov.vehicle.ivi.sec

import android.os.Parcel
import net.hwyz.iov.vehicle.ivi.sec.api.CertificateInfo
import net.hwyz.iov.vehicle.ivi.sec.api.DeviceToken
import net.hwyz.iov.vehicle.ivi.sec.api.SecContract
import net.hwyz.iov.vehicle.ivi.sec.api.SecError
import net.hwyz.iov.vehicle.ivi.sec.api.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState as DomainSecState
import net.hwyz.iov.vehicle.ivi.sec.service.SecBinderErrors
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Contract tests between the published AAR constants and the domain implementation. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class SecContractTest {

    @Test
    fun stateCodesMatch() {
        DomainSecState.entries.forEach { state ->
            val apiCode = when (state) {
                DomainSecState.NOT_PROVISIONED -> SecState.NOT_PROVISIONED
                DomainSecState.PROVISIONING -> SecState.PROVISIONING
                DomainSecState.ISSUED_PENDING_CLOUD -> SecState.ISSUED_PENDING_CLOUD
                DomainSecState.ACTIVE -> SecState.ACTIVE
                DomainSecState.RENEW_DUE -> SecState.RENEW_DUE
                DomainSecState.BLOCKED -> SecState.BLOCKED
                DomainSecState.ERROR -> SecState.ERROR
            }
            assertEquals(state.code, apiCode, "state ${state.name}")
            assertEquals(state.name, SecState.nameOf(apiCode))
        }
    }

    @Test
    fun errorCodesMatch() {
        SecErrorCode.entries.forEach { error ->
            val apiCode = when (error) {
                SecErrorCode.OK -> SecError.OK
                SecErrorCode.NOT_PROVISIONED -> SecError.NOT_PROVISIONED
                SecErrorCode.CALLER_REJECTED -> SecError.CALLER_REJECTED
                SecErrorCode.INVALID_ARGUMENT -> SecError.INVALID_ARGUMENT
                SecErrorCode.KEY_UNAVAILABLE -> SecError.KEY_UNAVAILABLE
                SecErrorCode.CERT_INVALID -> SecError.CERT_INVALID
                SecErrorCode.CERT_EXPIRED -> SecError.CERT_EXPIRED
                SecErrorCode.TOKEN_UNAVAILABLE -> SecError.TOKEN_UNAVAILABLE
                SecErrorCode.RATE_LIMITED -> SecError.RATE_LIMITED
                SecErrorCode.DEPENDENCY_UNAVAILABLE -> SecError.DEPENDENCY_UNAVAILABLE
                SecErrorCode.DEVICE_BLOCKED -> SecError.DEVICE_BLOCKED
                SecErrorCode.SESSION_CONFLICT -> SecError.SESSION_CONFLICT
            }
            assertEquals(error.code, apiCode, "error ${error.name}")
            assertEquals(error.name, SecError.nameOf(apiCode))
            assertEquals(error.retryable, SecError.isRetryable(apiCode))
        }
    }

    @Test
    fun wireMessagesAreStable() {
        assertTrue(SecError.wireMessage(SecError.CERT_INVALID).startsWith(SecError.WIRE_PREFIX))
        assertEquals("IVI_SEC:5:CERT_INVALID", SecError.wireMessage(SecError.CERT_INVALID))
        assertEquals(5, SecError.codeOfWireMessage(SecError.wireMessage(SecError.CERT_INVALID)))
        assertNull(SecError.codeOfWireMessage("random failure"))
        assertNull(SecError.codeOfWireMessage(null))

        val rejection = SecBinderErrors.toThrowable(SecErrorCode.CALLER_REJECTED)
        assertIs<SecurityException>(rejection)
        assertEquals(SecError.CALLER_REJECTED, SecError.codeOfWireMessage(rejection.message))

        val other = SecBinderErrors.toThrowable(SecErrorCode.DEPENDENCY_UNAVAILABLE)
        assertIs<IllegalStateException>(other)
        assertEquals(SecError.DEPENDENCY_UNAVAILABLE, SecError.codeOfWireMessage(other.message))
    }

    @Test
    fun providerColumnsAreFrozen() {
        assertEquals(
            listOf("state", "device_id", "cert_sn", "not_after", "last_reason_code", "updated_at"),
            SecContract.STATE_COLUMNS.toList(),
        )
        val forbidden = listOf("token", "access_token", "nonce", "signature", "private_key", "proof")
        SecContract.STATE_COLUMNS.forEach { column ->
            forbidden.forEach { secret ->
                assertTrue(!column.contains(secret), "column $column must not expose $secret")
            }
        }
    }

    @Test
    fun parcelablesRoundTrip() {
        val certificate = CertificateInfo(
            deviceId = "SN-1",
            subject = "CN=SN-1",
            certSn = "AABB",
            notBeforeEpochMillis = 1,
            notAfterEpochMillis = 2,
            fingerprintSha256 = "FF",
            state = SecState.ACTIVE,
        )
        val parcel = Parcel.obtain()
        try {
            certificate.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            assertEquals(certificate, CertificateInfo.CREATOR.createFromParcel(parcel))
        } finally {
            parcel.recycle()
        }

        val token = DeviceToken("access", arrayOf("vehicle.activation"), 3, 4)
        val tokenParcel = Parcel.obtain()
        try {
            token.writeToParcel(tokenParcel, 0)
            tokenParcel.setDataPosition(0)
            val restored = DeviceToken.CREATOR.createFromParcel(tokenParcel)
            assertEquals("access", restored.accessToken)
            assertTrue(arrayOf("vehicle.activation").contentEquals(restored.scopes))
            assertEquals(3, restored.issuedAtEpochMillis)
            assertEquals(4, restored.expiresAtEpochMillis)
        } finally {
            tokenParcel.recycle()
        }
    }
}
