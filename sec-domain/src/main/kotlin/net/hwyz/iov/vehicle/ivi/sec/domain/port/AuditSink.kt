package net.hwyz.iov.vehicle.ivi.sec.domain.port

/** Audited operations (IVI-SEC-SPEC D-011). */
enum class AuditOperation {
    STATE_QUERY,
    SIGN_NONCE,
    GET_DEVICE_TOKEN,
    INVALIDATE_TOKEN,
    PROVISION,
    IMPORT_CERTIFICATE,
}

enum class AuditOutcome {
    OK,
    REJECTED,
    FAILED,
}

/**
 * One local audit record. Contains identifiers and verdicts only: no token, nonce, signature,
 * certificate body or full device serial.
 */
data class AuditEntry(
    val timestampEpochMillis: Long,
    val uid: Int,
    val packageName: String?,
    val operation: AuditOperation,
    val outcome: AuditOutcome,
    val reasonCode: Int,
    val durationMillis: Long,
)

/**
 * Audit sink. A failing sink must not change the security verdict (US-005); the facade logs a
 * warning and keeps the original result.
 */
interface AuditSink {
    fun record(entry: AuditEntry)
}
