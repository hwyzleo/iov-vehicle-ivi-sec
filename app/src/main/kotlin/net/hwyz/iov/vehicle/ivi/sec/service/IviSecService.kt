package net.hwyz.iov.vehicle.ivi.sec.service

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import kotlinx.coroutines.runBlocking
import net.hwyz.iov.vehicle.ivi.sec.SecGraph
import net.hwyz.iov.vehicle.ivi.sec.api.CertificateInfo
import net.hwyz.iov.vehicle.ivi.sec.api.DeviceToken
import net.hwyz.iov.vehicle.ivi.sec.api.IIviSecService
import net.hwyz.iov.vehicle.ivi.sec.domain.SecException
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.secGraph

/**
 * AIDL binding service (IVI-SEC-SPEC D-006).
 *
 * All caller facing failures are propagated as a public binder exception whose message is
 * `IVI_SEC:<code>:<NAME>` (see [SecBinderErrors]); the caller never receives null or a boolean
 * success flag.
 */
class IviSecService : Service() {

    private val graph: SecGraph get() = applicationContext.secGraph()

    private val binder = object : IIviSecService.Stub() {
        override fun getState(): Int = execute {
            graph.facade.state(Binder.getCallingUid())
        }

        override fun getDeviceId(): String? = execute {
            graph.facade.deviceId(Binder.getCallingUid())
        }

        override fun getCertificateInfo(): CertificateInfo = execute {
            val info = graph.facade.certificateInfo(Binder.getCallingUid())
            CertificateInfo(
                deviceId = info.deviceId,
                subject = info.subject,
                certSn = info.certSn,
                notBeforeEpochMillis = info.notBeforeEpochMillis,
                notAfterEpochMillis = info.notAfterEpochMillis,
                fingerprintSha256 = info.fingerprintSha256,
                state = info.state.code,
            )
        }

        override fun signNonce(nonce: ByteArray?): ByteArray = execute {
            graph.facade.signNonce(Binder.getCallingUid(), nonce ?: ByteArray(0))
        }

        override fun getDeviceToken(requestedScopes: Array<out String>?): DeviceToken = execute {
            val token = graph.facade.deviceToken(
                callerUid = Binder.getCallingUid(),
                requestedScopes = requestedScopes?.toList() ?: emptyList(),
            )
            DeviceToken(
                accessToken = token.accessToken,
                scopes = token.scopes.toTypedArray(),
                issuedAtEpochMillis = token.issuedAtEpochMillis,
                expiresAtEpochMillis = token.expiresAtEpochMillis,
            )
        }

        override fun invalidateDeviceToken() {
            execute {
                graph.facade.invalidateDeviceToken(Binder.getCallingUid())
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun <T> execute(block: suspend () -> T): T = try {
        runBlocking { block() }
    } catch (error: SecException) {
        throw SecBinderErrors.toThrowable(error.error)
    } catch (error: Exception) {
        // Unexpected local failure: fail closed with a stable, retryable code; log the type only.
        graph.logger.event("service.internal_error", "reason" to error.javaClass.simpleName)
        throw SecBinderErrors.toThrowable(SecErrorCode.KEY_UNAVAILABLE)
    }
}
