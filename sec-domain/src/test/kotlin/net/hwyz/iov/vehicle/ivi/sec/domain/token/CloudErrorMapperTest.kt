package net.hwyz.iov.vehicle.ivi.sec.domain.token

import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** IVI-SEC-SPEC §4.5: cloud code to local code mapping is frozen. */
class CloudErrorMapperTest {

    @Test
    @DisplayName("All documented device identity codes map to their local code")
    fun mapsDocumentedCodes() {
        assertEquals(SecErrorCode.CERT_INVALID, CloudErrorMapper.mapBusinessCode("701325"))
        assertEquals(SecErrorCode.DEPENDENCY_UNAVAILABLE, CloudErrorMapper.mapBusinessCode("701326"))
        assertEquals(SecErrorCode.DEVICE_BLOCKED, CloudErrorMapper.mapBusinessCode("701327"))
        assertEquals(SecErrorCode.DEVICE_BLOCKED, CloudErrorMapper.mapBusinessCode("701328"))
        assertEquals(SecErrorCode.SESSION_CONFLICT, CloudErrorMapper.mapBusinessCode("701329"))
        assertEquals(SecErrorCode.TOKEN_UNAVAILABLE, CloudErrorMapper.mapBusinessCode("701330"))
        assertEquals(SecErrorCode.TOKEN_UNAVAILABLE, CloudErrorMapper.mapBusinessCode("701331"))
        assertEquals(SecErrorCode.TOKEN_UNAVAILABLE, CloudErrorMapper.mapBusinessCode("999999"))
        assertEquals(SecErrorCode.TOKEN_UNAVAILABLE, CloudErrorMapper.mapBusinessCode(null))
    }

    @Test
    @DisplayName("Success codes and HTTP outcomes are classified")
    fun mapsHttpOutcomes() {
        assertTrue(CloudErrorMapper.isSuccess("000000"))
        assertTrue(CloudErrorMapper.isSuccess("0"))
        assertTrue(CloudErrorMapper.isSuccess("200"))
        assertTrue(CloudErrorMapper.isSuccess(null))
        assertFalse(CloudErrorMapper.isSuccess("701325"))

        assertNull(CloudErrorMapper.mapHttpStatus(200))
        assertEquals(SecErrorCode.DEPENDENCY_UNAVAILABLE, CloudErrorMapper.mapHttpStatus(500))
        assertEquals(SecErrorCode.DEPENDENCY_UNAVAILABLE, CloudErrorMapper.mapHttpStatus(503))
        assertEquals(SecErrorCode.DEPENDENCY_UNAVAILABLE, CloudErrorMapper.mapHttpStatus(429))
        assertEquals(SecErrorCode.TOKEN_UNAVAILABLE, CloudErrorMapper.mapHttpStatus(400))
        assertEquals(SecErrorCode.TOKEN_UNAVAILABLE, CloudErrorMapper.mapHttpStatus(401))
    }
}
