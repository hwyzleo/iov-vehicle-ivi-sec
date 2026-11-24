package net.hwyz.iov.vehicle.ivi.sec.domain.port

/**
 * Resolved caller identity for admission control (IVI-SEC-SPEC D-007).
 *
 * [signedByService] is true only when every signing certificate digest of the caller package equals
 * the digest of the service package itself.
 */
data class CallerDescriptor(
    val uid: Int,
    val packageName: String?,
    val signatureSha256: String?,
    val signedByService: Boolean,
)

/** UID to package and signature resolution, implemented by the platform layer. */
fun interface CallerVerifier {
    fun describe(uid: Int): CallerDescriptor
}
