package net.hwyz.iov.vehicle.ivi.sec.domain.crypto

/**
 * Device certificate request profile shared with the TBOX SEC profile.
 *
 * Subject: CN=<hsm_uid>, OU=IVI-TSP, O=OpenIOV, C=CN
 * SAN:     URI:urn:ecu-uid:<hsm_uid>
 * KU:      digitalSignature + keyAgreement
 * EKU:     clientAuth only
 *
 * The HSM UID is the same identity value used by the TBOX. On devices where the vendor does not
 * expose it (for example the current Xiaomi tablet), the deployment supplies a provisioned value.
 */
data class CsrProfile(
    val commonName: String,
    val organizationalUnit: String = DEFAULT_ORGANIZATIONAL_UNIT,
    val organization: String = DEFAULT_ORGANIZATION,
    val country: String = DEFAULT_COUNTRY,
    val sanUriPrefix: String = DEFAULT_SAN_URI_PREFIX,
    val requestKeyAgreement: Boolean = true,
) {
    init {
        require(commonName.isNotBlank()) { "common name is blank" }
        require(organizationalUnit.isNotBlank()) { "organizational unit is blank" }
        require(organization.isNotBlank()) { "organization is blank" }
        require(country.isNotBlank()) { "country is blank" }
        require(sanUriPrefix.isNotBlank()) { "SAN URI prefix is blank" }
    }

    val sanUri: String get() = sanUriPrefix + commonName

    companion object {
        const val DEFAULT_ORGANIZATION = "OpenIOV"
        const val DEFAULT_ORGANIZATIONAL_UNIT = "IVI-TSP"
        const val DEFAULT_COUNTRY = "CN"
        const val DEFAULT_SAN_URI_PREFIX = "urn:ecu-uid:"
    }
}
