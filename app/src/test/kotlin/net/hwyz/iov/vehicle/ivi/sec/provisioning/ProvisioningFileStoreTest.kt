package net.hwyz.iov.vehicle.ivi.sec.provisioning

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Engineering provisioning channel: files must round-trip without a documents provider. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ProvisioningFileStoreTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val store = ProvisioningFileStore(context)

    @Test
    fun writesCsrToInternalAndExternalStorage() {
        val written = store.writeCsr("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n")

        assertTrue(written.isNotEmpty())
        assertTrue(File(context.filesDir, ProvisioningFileStore.CSR_FILE_NAME).isFile)
        written.forEach { file ->
            assertTrue(file.isFile, "written CSR missing: $file")
            assertTrue(file.readText().startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
        }
        assertEquals(
            "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
            store.readCsr(),
        )
    }

    @Test
    fun readCsrReturnsNullWhenMissingOrInvalid() {
        File(context.filesDir, ProvisioningFileStore.CSR_FILE_NAME).delete()
        assertNull(store.readCsr())

        File(context.filesDir, ProvisioningFileStore.CSR_FILE_NAME).writeText("not a csr")
        assertNull(store.readCsr())
    }

    @Test
    fun findsChainFileExternalFirstThenInternal() {
        val externalDir = context.getExternalFilesDir(null)
        if (externalDir != null) {
            val external = File(externalDir, ProvisioningFileStore.CHAIN_PEM_FILE)
            external.writeText("-----BEGIN CERTIFICATE-----\nexternal\n-----END CERTIFICATE-----\n")
            assertEquals(external, store.findChainFile())
            external.delete()
        }

        val internal = File(context.filesDir, ProvisioningFileStore.CHAIN_DER_FILE)
        internal.writeBytes(byteArrayOf(1, 2, 3))
        val found = store.findChainFile()
        assertNotNull(found)
        assertEquals(internal, found)

        internal.delete()
        assertNull(store.findChainFile())
    }

    @Test
    fun candidatesCoverPemAndDerInBothStores() {
        val names = store.chainTargets().map { it.name }
        assertTrue(names.contains(ProvisioningFileStore.CHAIN_PEM_FILE))
        assertTrue(names.contains(ProvisioningFileStore.CHAIN_DER_FILE))
    }
}
