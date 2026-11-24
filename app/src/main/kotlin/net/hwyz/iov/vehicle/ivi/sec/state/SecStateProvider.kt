package net.hwyz.iov.vehicle.ivi.sec.state

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import kotlinx.coroutines.runBlocking
import net.hwyz.iov.vehicle.ivi.sec.api.SecContract
import net.hwyz.iov.vehicle.ivi.sec.domain.ProviderSnapshot
import net.hwyz.iov.vehicle.ivi.sec.secGraph

/**
 * Read-only security state provider (IVI-SEC-SPEC D-006 / §4.7).
 *
 * Exposes one row with state, identifiers and certificate dates. Tokens, signatures and key material
 * have no column and can never be queried.
 */
class SecStateProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val snapshot = runBlocking { requireNotNull(context).secGraph().facade.providerSnapshot() }
        val columns = projection ?: SecContract.STATE_COLUMNS
        val cursor = MatrixCursor(columns)
        cursor.addRow(columns.map { column -> valueOf(column, snapshot) })
        return cursor
    }

    override fun getType(uri: Uri): String = SecContract.TOKEN_RESPONSE_MIME_TYPE

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    private fun valueOf(column: String, snapshot: ProviderSnapshot): Any? = when (column) {
        SecContract.COLUMN_STATE -> snapshot.state
        SecContract.COLUMN_DEVICE_ID -> snapshot.deviceId
        SecContract.COLUMN_CERT_SN -> snapshot.certSn
        SecContract.COLUMN_NOT_AFTER -> snapshot.notAfterEpochMillis
        SecContract.COLUMN_LAST_REASON_CODE -> snapshot.lastReasonCode
        SecContract.COLUMN_UPDATED_AT -> snapshot.updatedAtEpochMillis
        else -> null
    }
}
