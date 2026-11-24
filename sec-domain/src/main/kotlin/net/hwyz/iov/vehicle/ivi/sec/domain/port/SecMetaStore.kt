package net.hwyz.iov.vehicle.ivi.sec.domain.port

import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta

/** Non-secret metadata persistence (IVI-SEC-SPEC D-009). */
interface SecMetaStore {
    suspend fun read(): SecMeta

    suspend fun write(meta: SecMeta)
}
