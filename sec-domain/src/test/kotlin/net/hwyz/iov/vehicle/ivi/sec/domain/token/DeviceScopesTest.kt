package net.hwyz.iov.vehicle.ivi.sec.domain.token

import net.hwyz.iov.vehicle.ivi.sec.domain.SecException
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** US-004 / A-012: callers may narrow the device scope set but never widen it. */
class DeviceScopesTest {

    private val scopes = DeviceScopes(listOf("vehicle.activation", "vehicle.privacy.report"))

    @Test
    @DisplayName("Empty request means the full device scope set")
    fun defaultsToDeviceScopes() {
        assertEquals(listOf("vehicle.activation", "vehicle.privacy.report"), scopes.normalize(emptyList()))
    }

    @Test
    @DisplayName("A requested subset is accepted and normalized")
    fun acceptsSubset() {
        assertEquals(
            listOf("vehicle.privacy.report"),
            scopes.normalize(listOf(" vehicle.privacy.report ", "vehicle.privacy.report")),
        )
    }

    @Test
    @DisplayName("Account level and unknown scopes are rejected")
    fun rejectsWidening() {
        val error = assertFailsWith<SecException> {
            scopes.normalize(listOf("user.profile"))
        }
        assertEquals(SecErrorCode.INVALID_ARGUMENT, error.error)
        assertFailsWith<SecException> { scopes.normalize(listOf(" ")) }
    }

    @Test
    @DisplayName("Encoding and decoding use the space separated cloud form")
    fun encodesAndDecodes() {
        val encoded = scopes.encode(scopes.values)
        assertEquals("vehicle.activation vehicle.privacy.report", encoded)
        assertEquals(scopes.values, scopes.decode(encoded))
        assertEquals(emptyList(), scopes.decode(null))
    }
}
