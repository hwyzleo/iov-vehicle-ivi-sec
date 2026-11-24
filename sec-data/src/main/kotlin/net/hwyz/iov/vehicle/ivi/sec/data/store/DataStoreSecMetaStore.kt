package net.hwyz.iov.vehicle.ivi.sec.data.store

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecMeta
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.port.SecMetaStore

/**
 * DataStore backed non-secret metadata (IVI-SEC-SPEC D-009 / §6).
 *
 * Only identifiers, certificate validity dates, state and reason codes are stored. Tokens, nonces,
 * signatures and key material never reach this store.
 */
class DataStoreSecMetaStore(
    private val dataStore: DataStore<Preferences>,
) : SecMetaStore {

    override suspend fun read(): SecMeta {
        val preferences = dataStore.data.first()
        return SecMeta(
            deviceId = preferences[Keys.DEVICE_ID],
            certSn = preferences[Keys.CERT_SN],
            subject = preferences[Keys.SUBJECT],
            notBeforeEpochMillis = preferences[Keys.NOT_BEFORE] ?: 0L,
            notAfterEpochMillis = preferences[Keys.NOT_AFTER] ?: 0L,
            state = SecState.fromCode(preferences[Keys.STATE] ?: SecState.NOT_PROVISIONED.code)
                ?: SecState.NOT_PROVISIONED,
            lastReasonCode = preferences[Keys.LAST_REASON_CODE] ?: 0,
            lastIssuedAtEpochMillis = preferences[Keys.LAST_ISSUED_AT] ?: 0L,
            updatedAtEpochMillis = preferences[Keys.UPDATED_AT] ?: 0L,
        )
    }

    override suspend fun write(meta: SecMeta) {
        dataStore.edit { preferences ->
            preferences.putNullable(Keys.DEVICE_ID, meta.deviceId)
            preferences.putNullable(Keys.CERT_SN, meta.certSn)
            preferences.putNullable(Keys.SUBJECT, meta.subject)
            preferences[Keys.NOT_BEFORE] = meta.notBeforeEpochMillis
            preferences[Keys.NOT_AFTER] = meta.notAfterEpochMillis
            preferences[Keys.STATE] = meta.state.code
            preferences[Keys.LAST_REASON_CODE] = meta.lastReasonCode
            preferences[Keys.LAST_ISSUED_AT] = meta.lastIssuedAtEpochMillis
            preferences[Keys.UPDATED_AT] = meta.updatedAtEpochMillis
        }
    }

    private fun androidx.datastore.preferences.core.MutablePreferences.putNullable(
        key: Preferences.Key<String>,
        value: String?,
    ) {
        if (value == null) remove(key) else set(key, value)
    }

    private object Keys {
        val DEVICE_ID = stringPreferencesKey("device_id")
        val CERT_SN = stringPreferencesKey("cert_sn")
        val SUBJECT = stringPreferencesKey("subject")
        val NOT_BEFORE = longPreferencesKey("not_before")
        val NOT_AFTER = longPreferencesKey("not_after")
        val STATE = intPreferencesKey("state")
        val LAST_REASON_CODE = intPreferencesKey("last_reason_code")
        val LAST_ISSUED_AT = longPreferencesKey("last_issued_at")
        val UPDATED_AT = longPreferencesKey("updated_at")
    }

    companion object {
        const val FILE_NAME = "sec_meta"

        /** Production wiring: one process wide store backed by `files/datastore/sec_meta`. */
        fun create(context: Context): DataStoreSecMetaStore {
            val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val store = PreferenceDataStoreFactory.create(scope = scope) {
                context.preferencesDataStoreFile(FILE_NAME)
            }
            return DataStoreSecMetaStore(store)
        }
    }
}
