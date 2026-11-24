package net.hwyz.iov.vehicle.ivi.sec.domain.admission

import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor

/**
 * Caller allowlist policy (IVI-SEC-SPEC D-007).
 *
 * The platform permission is the first gate; this policy adds package and signature identity so a
 * same-signature but unregistered application cannot use the service.
 */
class CallerPolicy(private val whitelist: Set<String>) {

    fun isAllowed(caller: CallerDescriptor?): Boolean {
        if (caller == null) return false
        if (caller.uid <= 0) return false
        if (!caller.signedByService) return false
        val packageName = caller.packageName ?: return false
        return packageName in whitelist
    }

    fun whitelistSnapshot(): Set<String> = whitelist.toSet()
}
