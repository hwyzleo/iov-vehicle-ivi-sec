package net.hwyz.iov.vehicle.ivi.sec.service

import net.hwyz.iov.vehicle.ivi.sec.api.SecError
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode

/**
 * Translates a domain failure into a binder visible throwable.
 *
 * `android.app.ServiceSpecificException` is not part of the public SDK, so the documented error code
 * travels in a stable message (`IVI_SEC:<code>:<NAME>`, see [SecError.wireMessage]). Caller rejections
 * use [SecurityException]; every other failure uses [IllegalStateException]. Both are propagated by
 * binder, so a caller never observes a silent null success.
 */
internal object SecBinderErrors {

    fun toThrowable(error: SecErrorCode): RuntimeException = when (error) {
        SecErrorCode.CALLER_REJECTED -> SecurityException(SecError.wireMessage(error.code))
        else -> IllegalStateException(SecError.wireMessage(error.code))
    }
}
