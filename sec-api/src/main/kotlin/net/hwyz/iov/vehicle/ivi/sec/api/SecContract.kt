package net.hwyz.iov.vehicle.ivi.sec.api

import android.content.Intent

/**
 * Cross-application contract constants (IVI-SEC-SPEC §4.6 / §4.7).
 *
 * Callers resolve the service by package + action and query the read-only provider by authority.
 * Both components are guarded by signature level permissions.
 */
object SecContract {
    const val SERVICE_PACKAGE = "net.hwyz.iov.vehicle.ivi.sec"
    const val SERVICE_CLASS = "net.hwyz.iov.vehicle.ivi.sec.service.IviSecService"
    const val SERVICE_ACTION = "net.hwyz.iov.vehicle.ivi.sec.action.IIVI_SEC_SERVICE"

    const val USE_DEVICE_IDENTITY_PERMISSION =
        "net.hwyz.iov.vehicle.ivi.sec.permission.USE_DEVICE_IDENTITY"
    const val READ_STATE_PERMISSION =
        "net.hwyz.iov.vehicle.ivi.sec.permission.READ_STATE"

    const val STATE_AUTHORITY = "net.hwyz.iov.vehicle.ivi.sec.state"
    const val COLUMN_STATE = "state"
    const val COLUMN_DEVICE_ID = "device_id"
    const val COLUMN_CERT_SN = "cert_sn"
    const val COLUMN_NOT_AFTER = "not_after"
    const val COLUMN_LAST_REASON_CODE = "last_reason_code"
    const val COLUMN_UPDATED_AT = "updated_at"

    /** Provider result columns; the order is part of the contract. */
    val STATE_COLUMNS: Array<String> = arrayOf(
        COLUMN_STATE,
        COLUMN_DEVICE_ID,
        COLUMN_CERT_SN,
        COLUMN_NOT_AFTER,
        COLUMN_LAST_REASON_CODE,
        COLUMN_UPDATED_AT,
    )

    const val TOKEN_RESPONSE_MIME_TYPE = "vnd.android.cursor.item/vnd.$STATE_AUTHORITY"

    /** Intent a caller uses to bind [IIviSecService] (explicit package, no implicit resolution). */
    fun serviceIntent(): Intent = Intent(SERVICE_ACTION).setPackage(SERVICE_PACKAGE)
}
