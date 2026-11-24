package net.hwyz.iov.vehicle.ivi.sec.data.store

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** IVI-SEC-SPEC D-009: only non-secret metadata round-trips through DataStore. */
@OptIn(ExperimentalCoroutinesApi::class)
class DataStoreSecMetaStoreTest {

    @TempDir
    lateinit var tempDir: File

    private lateinit var scope: CoroutineScope
    private lateinit var dataStore: DataStore<Preferences>
    private lateinit var store: DataStoreSecMetaStore

    @BeforeEach
    fun setUp() {
        scope = CoroutineScope(UnconfinedTestDispatcher() + Job())
        dataStore = PreferenceDataStoreFactory.create(scope = scope) {
            File(tempDir, "sec_meta.preferences_pb")
        }
        store = DataStoreSecMetaStore(dataStore)
    }

    @AfterEach
    fun tearDown() {
        scope.cancel()
    }

    @Test
    @DisplayName("An empty store reads as NOT_PROVISIONED with absent dates")
    fun readsDefaults() = runTest {
        val meta = store.read()
        assertEquals(SecState.NOT_PROVISIONED, meta.state)
        assertNull(meta.deviceId)
        assertNull(meta.certSn)
        assertEquals(0, meta.notAfterEpochMillis)
        assertEquals(0, meta.lastReasonCode)
    }

    @Test
    @DisplayName("All metadata fields round-trip")
    fun roundTrips() = runTest {
        val meta = SecMeta(
            deviceId = "SN-TEST-001",
            certSn = "1A2B3C",
            subject = "CN=SN-TEST-001",
            notBeforeEpochMillis = 1_000,
            notAfterEpochMillis = 2_000,
            state = SecState.ACTIVE,
            lastReasonCode = 0,
            lastIssuedAtEpochMillis = 3_000,
            updatedAtEpochMillis = 4_000,
        )
        store.write(meta)
        assertEquals(meta, store.read())
    }

    @Test
    @DisplayName("Writing null identifiers clears the previous values")
    fun clearsNullableFields() = runTest {
        store.write(SecMeta(deviceId = "SN-1", certSn = "AA", subject = "CN=SN-1"))
        store.write(SecMeta(deviceId = null, certSn = null, subject = null, state = SecState.BLOCKED))
        val meta = store.read()
        assertNull(meta.deviceId)
        assertNull(meta.certSn)
        assertNull(meta.subject)
        assertEquals(SecState.BLOCKED, meta.state)
    }

    @Test
    @DisplayName("An unknown persisted state code falls back to NOT_PROVISIONED")
    fun unknownStateFallsBack() = runTest {
        dataStore.edit { it[intPreferencesKey("state")] = 99 }
        assertEquals(SecState.NOT_PROVISIONED, store.read().state)
    }
}
