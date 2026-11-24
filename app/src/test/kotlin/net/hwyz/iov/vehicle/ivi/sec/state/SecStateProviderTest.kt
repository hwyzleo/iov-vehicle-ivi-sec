package net.hwyz.iov.vehicle.ivi.sec.state

import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import net.hwyz.iov.vehicle.ivi.sec.IviSecApplication
import net.hwyz.iov.vehicle.ivi.sec.SecGraph
import net.hwyz.iov.vehicle.ivi.sec.api.SecContract
import net.hwyz.iov.vehicle.ivi.sec.api.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.clock.Clock
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState as DomainSecState
import net.hwyz.iov.vehicle.ivi.sec.domain.port.NoOpDiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.support.FixedCallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.support.FixedTokenPort
import net.hwyz.iov.vehicle.ivi.sec.support.InMemoryDeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.support.InMemoryMetaStore
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** IVI-SEC-SPEC §4.7: the provider is a read-only, non-secret state surface. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], application = IviSecApplication::class)
class SecStateProviderTest {

    private lateinit var application: IviSecApplication
    private lateinit var provider: SecStateProvider

    @Before
    fun setUp() {
        application = ApplicationProvider.getApplicationContext()
        application.graphOverride = SecGraph(
            context = application,
            deviceKeyPort = InMemoryDeviceKeyPort(keyPresent = true),
            metaStore = InMemoryMetaStore(
                SecMeta(deviceId = "SN-UNIT-001", state = DomainSecState.PROVISIONING),
            ),
            callerVerifier = FixedCallerVerifier(),
            deviceIdProvider = { "SN-UNIT-001" },
            tokenClient = FixedTokenPort(),
            callerWhitelist = setOf("net.hwyz.iov.vehicle.ivi.acc.demo"),
            logger = NoOpDiagnosticsLogger,
            clock = Clock { 1_000L },
        )
        provider = Robolectric.buildContentProvider(SecStateProvider::class.java).create().get()
    }

    @After
    fun tearDown() {
        application.graphOverride = null
    }

    private fun stateUri(): Uri = Uri.parse("content://${SecContract.STATE_AUTHORITY}/state")

    @Test
    fun queryReturnsOneRowWithContractColumns() {
        val cursor = requireNotNull(provider.query(stateUri(), null, null, null, null))
        try {
            assertEquals(1, cursor.count)
            assertEquals(SecContract.STATE_COLUMNS.toList(), cursor.columnNames.toList())
            cursor.moveToFirst()
            assertEquals(SecState.PROVISIONING, cursor.getInt(cursor.getColumnIndexOrThrow(SecContract.COLUMN_STATE)))
            assertEquals("SN-UNIT-001", cursor.getString(cursor.getColumnIndexOrThrow(SecContract.COLUMN_DEVICE_ID)))
            assertEquals(-1, cursor.getColumnIndex("access_token"))
            assertEquals(-1, cursor.getColumnIndex("signature"))
        } finally {
            cursor.close()
        }
    }

    @Test
    fun providerIsReadOnly() {
        assertNull(provider.insert(stateUri(), null))
        assertEquals(0, provider.update(stateUri(), null, null, null))
        assertEquals(0, provider.delete(stateUri(), null, null))
        assertEquals(SecContract.TOKEN_RESPONSE_MIME_TYPE, provider.getType(stateUri()))
    }
}
