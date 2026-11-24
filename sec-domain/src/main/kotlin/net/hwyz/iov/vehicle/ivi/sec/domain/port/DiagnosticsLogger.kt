package net.hwyz.iov.vehicle.ivi.sec.domain.port

/**
 * Structured diagnostics sink (IVI-SEC-SPEC D-011).
 *
 * Only whitelisted attributes may be emitted: caller package, operation, state, error code,
 * duration, cloud business code. Tokens, nonces, signatures, private keys, certificate bodies and
 * full device serials are dropped even when a call site passes them.
 */
interface DiagnosticsLogger {
    fun event(stage: String, vararg attributes: Pair<String, String>)
}

object NoOpDiagnosticsLogger : DiagnosticsLogger {
    override fun event(stage: String, vararg attributes: Pair<String, String>) = Unit
}

object Redaction {
    /** Attribute keys (lower case, separators removed) that must never reach a log sink. */
    val SENSITIVE_KEYS: Set<String> = setOf(
        "token",
        "accesstoken",
        "refreshtoken",
        "proof",
        "nonce",
        "signature",
        "privatekey",
        "certificate",
        "certbody",
        "deviceid",
        "serial",
        "secret",
        "credential",
        "authorization",
    )

    fun isSensitive(key: String): Boolean = key.lowercase().replace("_", "").replace("-", "") in SENSITIVE_KEYS

    fun filter(attributes: Array<out Pair<String, String>>): List<Pair<String, String>> =
        attributes.filterNot { (key, _) -> isSensitive(key) }
}

/** Test and demo sink that records the rendered, already redacted lines. */
class RecordingDiagnosticsLogger(
    private val sink: (String) -> Unit = {},
) : DiagnosticsLogger {
    private val lines = mutableListOf<String>()

    val entries: List<String> get() = synchronized(lines) { lines.toList() }

    override fun event(stage: String, vararg attributes: Pair<String, String>) {
        val rendered = Redaction.filter(attributes)
            .joinToString(separator = " ") { (key, value) -> "$key=$value" }
        val line = if (rendered.isEmpty()) stage else "$stage $rendered"
        synchronized(lines) { lines += line }
        sink(line)
    }
}
