package net.hwyz.iov.vehicle.ivi.sec.domain.audit

import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditEntry
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditOperation
import net.hwyz.iov.vehicle.ivi.sec.domain.port.AuditOutcome
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** US-005 / A-011: bounded local audit keeps the newest records only. */
class AuditRingBufferTest {

    private fun entry(index: Int) = AuditEntry(
        timestampEpochMillis = 1_000L + index,
        uid = 10_100,
        packageName = "net.hwyz.iov.vehicle.ivi.acc.demo",
        operation = AuditOperation.GET_DEVICE_TOKEN,
        outcome = AuditOutcome.OK,
        reasonCode = 0,
        durationMillis = 3,
    )

    @Test
    @DisplayName("Ring drops the oldest entry and keeps insertion order")
    fun keepsNewestEntries() {
        val ring = AuditRingBuffer(capacity = 3)
        repeat(5) { ring.record(entry(it)) }
        val entries = ring.snapshot()
        assertEquals(3, entries.size)
        assertEquals(listOf(2L, 3L, 4L), entries.map { it.timestampEpochMillis - 1_000 })
        assertEquals(3, ring.size())
    }

    @Test
    @DisplayName("Entries carry caller, operation, verdict, code and duration without secrets")
    fun recordsAuditFields() {
        val ring = AuditRingBuffer(capacity = 1)
        ring.record(entry(0))
        val record = ring.snapshot().single()
        assertEquals(10_100, record.uid)
        assertEquals("net.hwyz.iov.vehicle.ivi.acc.demo", record.packageName)
        assertEquals(AuditOperation.GET_DEVICE_TOKEN, record.operation)
        assertEquals(AuditOutcome.OK, record.outcome)
        assertEquals(0, record.reasonCode)
        assertEquals(3, record.durationMillis)
        assertTrue(ring.snapshot().isNotEmpty())
    }
}
