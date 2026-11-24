package net.hwyz.iov.vehicle.ivi.sec.data.cloud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceProof
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceTokenPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome
import net.hwyz.iov.vehicle.ivi.sec.domain.token.CloudErrorMapper
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit

/**
 * SEC-CIAM device identity grant client (IVI-SEC-SPEC §4.5).
 *
 * Sends a fresh KEY_SIGNATURE proof to `POST /api/ivi/auth/v1/token`. The request carries no
 * Authorization header (the device is not authenticated yet) and no secret is ever logged.
 */
class OkHttpDeviceTokenClient(
    private val baseUrl: String,
    private val clientId: String,
    private val tokenPath: String = DEFAULT_TOKEN_PATH,
    private val client: OkHttpClient = defaultClient(),
) : DeviceTokenPort {

    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun request(proof: DeviceProof, scopes: List<String>): TokenIssueOutcome =
        withContext(Dispatchers.IO) {
            val body = buildJsonObject {
                put("grantType", GRANT_DEVICE_IDENTITY)
                put("clientId", clientId)
                proof.deviceId?.let { put("deviceId", it) }
                put("proofType", proof.proofType)
                put("proof", proof.proofBase64)
                put("nonce", proof.nonceBase64)
                put("scope", scopes.joinToString(separator = " "))
            }.toString()
            val request = Request.Builder()
                .url(baseUrl.trimEnd('/') + tokenPath)
                .post(body.toRequestBody(JSON_MEDIA_TYPE))
                .build()
            val response = try {
                client.newCall(request).execute()
            } catch (timeout: SocketTimeoutException) {
                return@withContext TokenIssueOutcome.Failed(
                    SecErrorCode.DEPENDENCY_UNAVAILABLE,
                    message = "timeout",
                )
            } catch (error: IOException) {
                return@withContext TokenIssueOutcome.Failed(
                    SecErrorCode.DEPENDENCY_UNAVAILABLE,
                    message = "io-error",
                )
            }
            response.use { result ->
                val payload = result.body?.string()
                CloudErrorMapper.mapHttpStatus(result.code)?.let { mapped ->
                    return@use TokenIssueOutcome.Failed(mapped, cloudCode = "http-${result.code}")
                }
                decode(payload)
            }
        }

    private fun decode(payload: String?): TokenIssueOutcome {
        if (payload.isNullOrBlank()) {
            return TokenIssueOutcome.Failed(SecErrorCode.TOKEN_UNAVAILABLE, message = "empty-body")
        }
        val envelope = runCatching { json.parseToJsonElement(payload).jsonObject }.getOrNull()
            ?: return TokenIssueOutcome.Failed(SecErrorCode.TOKEN_UNAVAILABLE, message = "unparsable-body")
        val code = envelope.string("code")
        val message = envelope.string("message")
        if (!CloudErrorMapper.isSuccess(code)) {
            return TokenIssueOutcome.Failed(
                error = CloudErrorMapper.mapBusinessCode(code),
                cloudCode = code,
                message = message,
            )
        }
        val data = envelope["data"] as? JsonObject
            ?: return TokenIssueOutcome.Failed(SecErrorCode.TOKEN_UNAVAILABLE, cloudCode = code, message = "no-data")
        val accessToken = data.string("access_token")
            ?: return TokenIssueOutcome.Failed(
                SecErrorCode.TOKEN_UNAVAILABLE,
                cloudCode = code,
                message = "no-access-token",
            )
        val expiresIn = (data["expires_in"] as? JsonPrimitive)?.content?.toLongOrNull()
            ?: DEFAULT_TTL_SECONDS
        return TokenIssueOutcome.Issued(
            accessToken = accessToken,
            expiresInSeconds = expiresIn,
            scope = data.string("scope"),
        )
    }

    companion object {
        const val DEFAULT_TOKEN_PATH = "/api/ivi/auth/v1/token"
        const val GRANT_DEVICE_IDENTITY = "urn:openiov:params:oauth:grant-type:device-identity"
        const val DEFAULT_TTL_SECONDS = 900L

        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()
    }
}

private fun JsonObject.string(name: String): String? = (this[name] as? JsonPrimitive)?.content
