package net.hwyz.iov.vehicle.ivi.sec.data.platform

import android.os.Build

/**
 * Best effort device serial number used as the CSR common name and `deviceId` claim.
 *
 * Order: `Build.getSerial()` (needs READ_PHONE_STATE or a privileged app), then legacy
 * `Build.SERIAL`.
 *
 * **BLK-4 (IVI-ACC-DSN-CR-005 D-011): the `Settings.Secure` device id fallback is removed.** It is
 * resettable, it collides across devices of the same model and it is not a factory identity; using it
 * produced a different `device_id` than the IVI-ACC reader and inevitably tripped CIAM `701329`
 * (device session conflict). When no serial is readable this returns `null` and the caller fails
 * closed (no device token, no activation request).
 *
 * The value is never logged.
 */
class AndroidDeviceSerialProvider {

    fun deviceId(): String? = serialFromBuild()

    private fun serialFromBuild(): String? {
        val apiSerial = runCatching { Build.getSerial() }.getOrNull()
        if (!apiSerial.isNullOrBlank() && apiSerial != Build.UNKNOWN) return apiSerial
        @Suppress("DEPRECATION")
        val legacy = Build.SERIAL
        if (!legacy.isNullOrBlank() && legacy != Build.UNKNOWN) return legacy
        return null
    }
}
