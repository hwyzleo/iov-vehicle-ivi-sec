package net.hwyz.iov.vehicle.ivi.sec.state

import android.content.ComponentName
import android.content.ContentValues
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.hwyz.iov.vehicle.ivi.sec.api.SecContract
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Instrumentation evidence for §4.6 / §4.7: permission protection and read-only provider. */
@RunWith(AndroidJUnit4::class)
class SecStateProviderInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val uri: Uri = Uri.parse("content://${SecContract.STATE_AUTHORITY}/state")

    @Test
    fun providerQueryReturnsContractColumns() {
        val cursor = context.contentResolver.query(uri, null, null, null, null)
        assertNotNull("provider query returned null", cursor)
        cursor!!
        try {
            assertEquals(1, cursor.count)
            assertEquals(SecContract.STATE_COLUMNS.toList(), cursor.columnNames.toList())
            cursor.moveToFirst()
            val state = cursor.getInt(cursor.getColumnIndexOrThrow(SecContract.COLUMN_STATE))
            assertTrue("state $state out of range", state in 0..6)
            assertEquals(-1, cursor.getColumnIndex("access_token"))
            assertEquals(-1, cursor.getColumnIndex("signature"))
        } finally {
            cursor.close()
        }
    }

    @Test
    fun providerIsReadOnly() {
        val inserted = runCatching { context.contentResolver.insert(uri, ContentValues()) }
        assertTrue(
            "insert must fail or return null: $inserted",
            inserted.isFailure || inserted.getOrNull() == null,
        )
        assertEquals(0, context.contentResolver.update(uri, ContentValues(), null, null))
        assertEquals(0, context.contentResolver.delete(uri, null, null))
    }

    @Test
    fun permissionsAndComponentsAreDeclaredAsDesigned() {
        val packageManager = context.packageManager

        val identity = packageManager.getPermissionInfo(SecContract.USE_DEVICE_IDENTITY_PERMISSION, 0)
        assertEquals(
            PermissionInfo.PROTECTION_SIGNATURE,
            identity.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE,
        )
        val readState = packageManager.getPermissionInfo(SecContract.READ_STATE_PERMISSION, 0)
        assertEquals(
            PermissionInfo.PROTECTION_SIGNATURE,
            readState.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE,
        )

        val service = packageManager.getServiceInfo(
            ComponentName(SecContract.SERVICE_PACKAGE, SecContract.SERVICE_CLASS),
            0,
        )
        assertTrue(service.exported)
        assertEquals(SecContract.USE_DEVICE_IDENTITY_PERMISSION, service.permission)

        val provider = packageManager.resolveContentProvider(SecContract.STATE_AUTHORITY, 0)
        assertNotNull(provider)
        assertTrue(provider!!.exported)
        assertEquals(SecContract.READ_STATE_PERMISSION, provider.readPermission)
    }
}
