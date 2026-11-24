package net.hwyz.iov.vehicle.ivi.sec.data.cloud

import kotlinx.coroutines.runBlocking
import net.hwyz.iov.vehicle.ivi.sec.domain.model.DeviceProof
import net.hwyz.iov.vehicle.ivi.sec.domain.model.SecErrorCode
import net.hwyz.iov.vehicle.ivi.sec.domain.port.TokenIssueOutcome
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** IVI-SEC-SPEC §4.5 contract test: request shape, cloud codes and transport failures. */
class OkHttpDeviceTokenClientTest {

    private lateinit var server: MockWebServer

    private val proof = DeviceProof(
        deviceId = "SN-TEST-001",
        proofType = "KEY_SIGNATURE",
        proofBase64 = "c2lnbmF0dXJl",
        nonceBase64 = "bm9uY2U=",
    )

    @BeforeEach
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun client(timeoutMillis: Long = 5_000): OkHttpDeviceTokenClient = OkHttpDeviceTokenClient(
        baseUrl = server.url("/").toString(),
        clientId = "ivi-capp",
        client = OkHttpClient.Builder()
            .connectTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            .writeTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            .build(),
    )

    private fun successBody(
        accessToken: String = "access-token-1",
        expiresIn: Long = 900,
        scope: String = "vehicle.activation",
    ): String = """{"code":"000000","data":{"access_token":"$accessToken","token_type":"Bearer","expires_in":$expiresIn,"scope":"$scope"}}"""

    @Test
    @DisplayName("Request carries the device identity grant, the proof and no Authorization header")
    fun sendsDocumentedRequest() = runBlocking {
        server.enqueue(MockResponse().setBody(successBody()))
        val outcome = client().request(proof, listOf("vehicle.activation", "vehicle.privacy.report"))
        assertIs<TokenIssueOutcome.Issued>(outcome)

        val request = server.takeRequest()
        assertEquals("/api/ivi/auth/v1/token", request.path)
        assertEquals("POST", request.method)
        assertNull(request.getHeader("Authorization"))
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"grantType\":\"${OkHttpDeviceTokenClient.GRANT_DEVICE_IDENTITY}\""))
        assertTrue(body.contains("\"clientId\":\"ivi-capp\""))
        assertTrue(body.contains("\"deviceId\":\"SN-TEST-001\""))
        assertTrue(body.contains("\"proofType\":\"KEY_SIGNATURE\""))
        assertTrue(body.contains("\"proof\":\"c2lnbmF0dXJl\""))
        assertTrue(body.contains("\"nonce\":\"bm9uY2U=\""))
        assertTrue(body.contains("\"scope\":\"vehicle.activation vehicle.privacy.report\""))
    }

    @Test
    @DisplayName("A successful response yields the access token, TTL and scope")
    fun parsesSuccess() = runBlocking {
        server.enqueue(MockResponse().setBody(successBody(accessToken = "token-abc", expiresIn = 900)))
        val outcome = assertIs<TokenIssueOutcome.Issued>(client().request(proof, emptyList()))
        assertEquals("token-abc", outcome.accessToken)
        assertEquals(900, outcome.expiresInSeconds)
        assertEquals("vehicle.activation", outcome.scope)
    }

    @Test
    @DisplayName("Missing expires_in falls back to the 15 minute TTL")
    fun defaultsTtl() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"code":"000000","data":{"access_token":"t"}}"""))
        val outcome = assertIs<TokenIssueOutcome.Issued>(client().request(proof, emptyList()))
        assertEquals(OkHttpDeviceTokenClient.DEFAULT_TTL_SECONDS, outcome.expiresInSeconds)
    }

    @Test
    @DisplayName("Every documented business code maps to the local code")
    fun mapsBusinessCodes() = runBlocking {
        val expected = mapOf(
            "701325" to SecErrorCode.CERT_INVALID,
            "701326" to SecErrorCode.DEPENDENCY_UNAVAILABLE,
            "701327" to SecErrorCode.DEVICE_BLOCKED,
            "701328" to SecErrorCode.DEVICE_BLOCKED,
            "701329" to SecErrorCode.SESSION_CONFLICT,
            "701330" to SecErrorCode.TOKEN_UNAVAILABLE,
            "701331" to SecErrorCode.TOKEN_UNAVAILABLE,
        )
        expected.forEach { (cloudCode, localCode) ->
            server.enqueue(MockResponse().setBody("""{"code":"$cloudCode","message":"rejected"}"""))
            val outcome = assertIs<TokenIssueOutcome.Failed>(client().request(proof, emptyList()))
            assertEquals(localCode, outcome.error, "cloud code $cloudCode")
            assertEquals(cloudCode, outcome.cloudCode)
        }
    }

    @Test
    @DisplayName("5xx and 429 are dependency failures; 4xx is a token failure")
    fun mapsHttpFailures() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(503))
        assertEquals(
            SecErrorCode.DEPENDENCY_UNAVAILABLE,
            assertIs<TokenIssueOutcome.Failed>(client().request(proof, emptyList())).error,
        )
        server.enqueue(MockResponse().setResponseCode(429))
        assertEquals(
            SecErrorCode.DEPENDENCY_UNAVAILABLE,
            assertIs<TokenIssueOutcome.Failed>(client().request(proof, emptyList())).error,
        )
        server.enqueue(MockResponse().setResponseCode(400))
        assertEquals(
            SecErrorCode.TOKEN_UNAVAILABLE,
            assertIs<TokenIssueOutcome.Failed>(client().request(proof, emptyList())).error,
        )
    }

    @Test
    @DisplayName("A timeout is a dependency failure")
    fun mapsTimeout() = runBlocking {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        val outcome = assertIs<TokenIssueOutcome.Failed>(client(timeoutMillis = 150).request(proof, emptyList()))
        assertEquals(SecErrorCode.DEPENDENCY_UNAVAILABLE, outcome.error)
    }

    @Test
    @DisplayName("Malformed or incomplete success bodies fail closed")
    fun rejectsBadBodies() = runBlocking {
        server.enqueue(MockResponse().setBody("not-json"))
        assertEquals(
            SecErrorCode.TOKEN_UNAVAILABLE,
            assertIs<TokenIssueOutcome.Failed>(client().request(proof, emptyList())).error,
        )
        server.enqueue(MockResponse().setBody("""{"code":"000000","data":{}}"""))
        assertEquals(
            SecErrorCode.TOKEN_UNAVAILABLE,
            assertIs<TokenIssueOutcome.Failed>(client().request(proof, emptyList())).error,
        )
        server.enqueue(MockResponse().setBody(""))
        assertEquals(
            SecErrorCode.TOKEN_UNAVAILABLE,
            assertIs<TokenIssueOutcome.Failed>(client().request(proof, emptyList())).error,
        )
    }
}
