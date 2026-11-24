package net.hwyz.iov.vehicle.ivi.sec.data.log

import android.util.Log
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.domain.port.Redaction

/**
 * Logcat diagnostics sink with the whitelist from IVI-SEC-SPEC §7.
 *
 * Sensitive keys are dropped before rendering, even if a call site passes them by mistake.
 */
class AndroidDiagnosticsLogger(
    private val tag: String = DEFAULT_TAG,
) : DiagnosticsLogger {

    override fun event(stage: String, vararg attributes: Pair<String, String>) {
        val rendered = Redaction.filter(attributes)
            .joinToString(separator = " ") { (key, value) -> "$key=$value" }
        Log.i(tag, if (rendered.isEmpty()) stage else "$stage $rendered")
    }

    companion object {
        const val DEFAULT_TAG = "IviSec"
    }
}
