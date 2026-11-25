package net.hwyz.iov.vehicle.ivi.sec.data.platform

/**
 * Where the resolved device SN came from (IVI-SEC-DSN-CR-002 D-003). Diagnostic only: it never
 * carries the value itself and never reaches the cloud.
 */
enum class DeviceSerialOrigin {
    /** Deploy time value (`BuildConfig.DEVICE_SN`), provisioned per vehicle by the line/bench. */
    DEPLOY,

    /** Platform read only serial (`Build.getSerial()` -> `Build.SERIAL`). */
    PLATFORM,

    /** Nothing usable: the caller MUST fail closed (no proof, no token, no activation request). */
    NONE,
}

/** A resolved device SN plus its origin. The value is never logged. */
data class ResolvedDeviceSerial(
    val value: String?,
    val origin: DeviceSerialOrigin,
) {
    val usable: Boolean get() = value != null
}

/**
 * Single source of truth for the CIAM `device_id` claim (IVI-SEC-DSN-CR-002 D-003 修订).
 *
 * Order, and only this order:
 * 1. the deploy time value (`BuildConfig.DEVICE_SN`) — head units commonly cannot read the platform
 *    serial at all, so the line/bench must supply the SN, exactly like it supplies `HSM_UID`;
 * 2. the platform read only serial;
 * 3. nothing → `null`, and the caller fails closed (D-012「不可用状态不得返回可用令牌」).
 *
 * `hsm_uid` is deliberately *not* a source: it is the security chip identity used for the
 * certificate subject / SAN (D-008), not the device SN, and the two must never be interchanged.
 */
object DeviceSerialResolver {

    /** Placeholder values that must never be sent as a device identity. */
    private val REJECTED = setOf("unknown", "0", "null")

    fun resolve(deployValue: String?, platformValue: () -> String?): ResolvedDeviceSerial {
        normalise(deployValue)?.let { return ResolvedDeviceSerial(it, DeviceSerialOrigin.DEPLOY) }
        normalise(runCatching(platformValue).getOrNull())
            ?.let { return ResolvedDeviceSerial(it, DeviceSerialOrigin.PLATFORM) }
        return ResolvedDeviceSerial(null, DeviceSerialOrigin.NONE)
    }

    private fun normalise(raw: String?): String? =
        raw?.trim()?.takeIf { it.isNotEmpty() }?.takeIf { it.lowercase() !in REJECTED }
}
