package net.hwyz.iov.vehicle.ivi.sec.domain.audit

import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditEntry
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditSink

/**
 * Bounded in-memory audit buffer (IVI-SEC-SPEC D-011).
 *
 * Capacity is a single constant; the retention question Q-010 is still open and only changes this
 * number, not the record shape.
 */
class AuditRingBuffer(private val capacity: Int = DEFAULT_CAPACITY) : AuditSink {

    init {
        require(capacity > 0) { "audit capacity must be positive" }
    }

    private val entries = ArrayDeque<AuditEntry>(capacity)

    override fun record(entry: AuditEntry) {
        synchronized(entries) {
            if (entries.size == capacity) entries.removeFirst()
            entries.addLast(entry)
        }
    }

    fun snapshot(): List<AuditEntry> = synchronized(entries) { entries.toList() }

    fun size(): Int = synchronized(entries) { entries.size }

    fun clear() {
        synchronized(entries) { entries.clear() }
    }

    companion object {
        const val DEFAULT_CAPACITY = 256
    }
}
