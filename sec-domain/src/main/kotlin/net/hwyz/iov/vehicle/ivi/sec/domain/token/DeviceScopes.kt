package net.hwyz.iov.vehicle.ivi.sec.domain.token

import net.hwyz.iov.vehicle.ivi.sec.domain.SecException
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode

/**
 * Device level scope policy (IVI-SEC-SPEC D-005).
 *
 * The service owns one fixed device scope set; callers may narrow it but never widen it, and account
 * level scopes are rejected instead of forwarded to the cloud.
 */
class DeviceScopes(allowed: List<String>) {

    val values: List<String> = allowed.map { it.trim() }.filter { it.isNotEmpty() }.distinct()

    init {
        require(values.isNotEmpty()) { "device scope set must not be empty" }
    }

    fun normalize(requested: List<String>): List<String> {
        if (requested.isEmpty()) return values
        val cleaned = requested.map { it.trim() }.filter { it.isNotEmpty() }
        if (cleaned.isEmpty()) throw SecException(SecErrorCode.INVALID_ARGUMENT, "empty scope entry")
        val unknown = cleaned.firstOrNull { it !in values }
        if (unknown != null) {
            throw SecException(SecErrorCode.INVALID_ARGUMENT, "scope not in device scope set")
        }
        return cleaned.distinct()
    }

    fun encode(scopes: List<String>): String = scopes.joinToString(separator = " ")

    fun decode(scope: String?): List<String> =
        scope?.split(' ')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
}
