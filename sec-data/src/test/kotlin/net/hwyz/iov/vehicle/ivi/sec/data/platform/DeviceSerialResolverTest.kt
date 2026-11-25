package net.hwyz.iov.vehicle.ivi.sec.data.platform

import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * IVI-SEC-DSN-CR-002 D-003: the CIAM `device_id` is the device SN, resolved from the deploy value
 * first and the platform serial second; anything unusable fails closed instead of being papered over.
 */
class DeviceSerialResolverTest {

    @Test
    @DisplayName("部署预置 SN 优先于平台序列号")
    fun deployValueWins() {
        val resolved = DeviceSerialResolver.resolve("00000005AA00000001") { "PLATFORM-SN" }
        assertEquals("00000005AA00000001", resolved.value)
        assertEquals(DeviceSerialOrigin.DEPLOY, resolved.origin)
    }

    @Test
    @DisplayName("部署值为空时回退平台序列号")
    fun platformIsTheFallback() {
        val resolved = DeviceSerialResolver.resolve("   ") { "PLATFORM-SN" }
        assertEquals("PLATFORM-SN", resolved.value)
        assertEquals(DeviceSerialOrigin.PLATFORM, resolved.origin)
    }

    @Test
    @DisplayName("占位值不得作为设备标识")
    fun placeholdersAreRejected() {
        listOf("unknown", "UNKNOWN", "0", "null").forEach { placeholder ->
            val resolved = DeviceSerialResolver.resolve(placeholder) { null }
            assertNull(resolved.value, "placeholder '$placeholder' must not be used")
            assertEquals(DeviceSerialOrigin.NONE, resolved.origin)
        }
    }

    @Test
    @DisplayName("平台读取抛异常时按不可用处理，不崩溃")
    fun platformFailureIsTolerated() {
        val resolved = DeviceSerialResolver.resolve(null) { error("denied") }
        assertNull(resolved.value)
        assertEquals(DeviceSerialOrigin.NONE, resolved.origin)
    }

    @Test
    @DisplayName("全部不可得时返回 null，由调用方失败关闭")
    fun unavailableStaysUnavailable() {
        val resolved = DeviceSerialResolver.resolve(null) { null }
        assertNull(resolved.value)
        assertEquals(DeviceSerialOrigin.NONE, resolved.origin)
        assertEquals(false, resolved.usable)
    }

    @Test
    @DisplayName("首尾空白被裁剪，其余内容原样保留（不做大小写归一）")
    fun valueIsTrimmedOnly() {
        assertEquals("00000005AA00000001", DeviceSerialResolver.resolve(" 00000005AA00000001 ") { null }.value)
        assertEquals("abcDEF-1", DeviceSerialResolver.resolve("abcDEF-1") { null }.value)
    }
}
