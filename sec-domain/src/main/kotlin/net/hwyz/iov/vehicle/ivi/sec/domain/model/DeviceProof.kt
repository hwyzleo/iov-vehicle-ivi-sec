package net.hwyz.iov.vehicle.ivi.sec.domain.model

/** Device proof material sent to SEC-CIAM (IVI-SEC-SPEC §4.5). Never logged. */
data class DeviceProof(
    val deviceId: String?,
    val proofType: String,
    val proofBase64: String,
    val nonceBase64: String,
)
