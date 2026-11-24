package net.hwyz.iov.vehicle.ivi.sec.data.caller

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerDescriptor
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerVerifier
import java.security.MessageDigest

/**
 * Resolves a binder UID to a package and compares its signing certificate digests with the service
 * package (IVI-SEC-SPEC D-007).
 *
 * A UID that cannot be resolved, or whose package is signed by another key, is reported as not
 * signed by the service and is rejected by the domain allowlist policy.
 */
class AndroidCallerIdentityProvider(
    private val context: Context,
    private val packageManager: PackageManager = context.packageManager,
) : CallerVerifier {

    private val ownSignatures: Set<String> by lazy { signatureDigests(context.packageName) }

    override fun describe(uid: Int): CallerDescriptor {
        val packageName = runCatching { packageManager.getPackagesForUid(uid) }
            .getOrNull()
            ?.firstOrNull()
            ?: return CallerDescriptor(uid, null, null, false)
        val signatures = runCatching { signatureDigests(packageName) }.getOrDefault(emptySet())
        val signedByService = signatures.isNotEmpty() && signatures.all { it in ownSignatures }
        return CallerDescriptor(
            uid = uid,
            packageName = packageName,
            signatureSha256 = signatures.firstOrNull(),
            signedByService = signedByService,
        )
    }

    private fun signatureDigests(packageName: String): Set<String> {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        val info = packageManager.getPackageInfo(packageName, flags)
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo ?: return emptySet()
            if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
        } else {
            @Suppress("DEPRECATION")
            info.signatures ?: return emptySet()
        }
        return signatures.mapTo(mutableSetOf()) { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
                .joinToString(separator = "") { "%02x".format(it) }
        }
    }
}
