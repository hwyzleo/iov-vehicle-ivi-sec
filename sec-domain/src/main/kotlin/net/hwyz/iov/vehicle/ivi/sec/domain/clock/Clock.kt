package net.hwyz.iov.vehicle.ivi.sec.domain.clock

/** Wall clock seam; all expiry and rate limit decisions use it (tests inject a fake). */
fun interface Clock {
    fun nowEpochMillis(): Long

    companion object {
        val System: Clock = Clock { java.lang.System.currentTimeMillis() }
    }
}
