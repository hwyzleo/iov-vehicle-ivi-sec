package net.hwyz.iov.vehicle.ivi.sec.domain

import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode

/**
 * A failure with a stable contract code. The service translates it to
 * `ServiceSpecificException(error.code)`; callers must never see a null or boolean failure.
 */
class SecException(
    val error: SecErrorCode,
    val reason: String? = null,
    cause: Throwable? = null,
) : Exception(reason ?: error.name, cause)
