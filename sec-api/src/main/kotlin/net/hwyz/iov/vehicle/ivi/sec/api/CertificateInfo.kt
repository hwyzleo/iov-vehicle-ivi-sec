package net.hwyz.iov.vehicle.ivi.sec.api

import android.os.Parcel
import android.os.Parcelable

/**
 * Non-secret view of the installed device certificate (IVI-SEC-SPEC §4.2).
 *
 * Never carries private key material, the device token or a signature.
 */
data class CertificateInfo(
    val deviceId: String?,
    val subject: String?,
    val certSn: String?,
    val notBeforeEpochMillis: Long,
    val notAfterEpochMillis: Long,
    val fingerprintSha256: String?,
    val state: Int,
) : Parcelable {

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeString(deviceId)
        dest.writeString(subject)
        dest.writeString(certSn)
        dest.writeLong(notBeforeEpochMillis)
        dest.writeLong(notAfterEpochMillis)
        dest.writeString(fingerprintSha256)
        dest.writeInt(state)
    }

    companion object CREATOR : Parcelable.Creator<CertificateInfo> {
        override fun createFromParcel(parcel: Parcel): CertificateInfo = CertificateInfo(
            deviceId = parcel.readString(),
            subject = parcel.readString(),
            certSn = parcel.readString(),
            notBeforeEpochMillis = parcel.readLong(),
            notAfterEpochMillis = parcel.readLong(),
            fingerprintSha256 = parcel.readString(),
            state = parcel.readInt(),
        )

        override fun newArray(size: Int): Array<CertificateInfo?> = arrayOfNulls(size)
    }
}
