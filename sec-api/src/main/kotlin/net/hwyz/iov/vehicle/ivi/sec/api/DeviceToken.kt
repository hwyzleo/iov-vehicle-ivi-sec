package net.hwyz.iov.vehicle.ivi.sec.api

import android.os.Parcel
import android.os.Parcelable

/**
 * Device identity token handed to a caller (IVI-SEC-SPEC §4.2).
 *
 * The token lives in memory only; callers must not persist it or hold it past [expiresAtEpochMillis].
 */
data class DeviceToken(
    val accessToken: String,
    val scopes: Array<String>,
    val issuedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
) : Parcelable {

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeString(accessToken)
        dest.writeStringArray(scopes)
        dest.writeLong(issuedAtEpochMillis)
        dest.writeLong(expiresAtEpochMillis)
    }

    companion object CREATOR : Parcelable.Creator<DeviceToken> {
        override fun createFromParcel(parcel: Parcel): DeviceToken = DeviceToken(
            accessToken = requireNotNull(parcel.readString()) { "accessToken" },
            scopes = parcel.createStringArray() ?: emptyArray(),
            issuedAtEpochMillis = parcel.readLong(),
            expiresAtEpochMillis = parcel.readLong(),
        )

        override fun newArray(size: Int): Array<DeviceToken?> = arrayOfNulls(size)
    }
}
