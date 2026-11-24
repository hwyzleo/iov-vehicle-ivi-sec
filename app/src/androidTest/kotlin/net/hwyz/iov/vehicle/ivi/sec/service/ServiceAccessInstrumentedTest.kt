package net.hwyz.iov.vehicle.ivi.sec.service

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.os.IBinder
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.hwyz.iov.vehicle.ivi.sec.IviSecApplication
import net.hwyz.iov.vehicle.ivi.sec.SecGraph
import net.hwyz.iov.vehicle.ivi.sec.api.IIviSecService
import net.hwyz.iov.vehicle.ivi.sec.api.SecContract
import net.hwyz.iov.vehicle.ivi.sec.api.SecError
import net.hwyz.iov.vehicle.ivi.sec.domain.port.NoOpDiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedCallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedClock
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedDeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedMetaStore
import net.hwyz.iov.vehicle.ivi.sec.support.InstrumentedTokenPort
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Binder evidence for §4.1 / §4.6: same-signature caller access, stable failure codes on the wire and
 * allowlist rejection. Cross-signature rejection is enforced by the platform signature permission and
 * is not executable from a same-signature test APK.
 */
@RunWith(AndroidJUnit4::class)
class ServiceAccessInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val targetContext = instrumentation.targetContext
    private val testPackage = instrumentation.context.packageName
    private lateinit var application: IviSecApplication

    @Before
    fun setUp() {
        application = targetContext.applicationContext as IviSecApplication
    }

    @After
    fun tearDown() {
        application.graphOverride = null
    }

    private fun graph(whitelist: Set<String>): SecGraph = SecGraph(
        context = application,
        deviceKeyPort = InstrumentedDeviceKeyPort(),
        metaStore = InstrumentedMetaStore(),
        callerVerifier = InstrumentedCallerVerifier(testPackage),
        deviceIdProvider = { "SN-SERVICE-TEST" },
        tokenClient = InstrumentedTokenPort(),
        callerWhitelist = whitelist,
        logger = NoOpDiagnosticsLogger,
        clock = InstrumentedClock(),
    )

    private fun <T> withService(block: (IIviSecService) -> T): T {
        val latch = CountDownLatch(1)
        var binder: IBinder? = null
        var connectionError: Throwable? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                binder = service
                latch.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }
        val bound = targetContext.bindService(
            SecContract.serviceIntent(),
            connection,
            Context.BIND_AUTO_CREATE,
        )
        assertTrue("bindService returned false", bound)
        assertTrue("service did not connect", latch.await(10, TimeUnit.SECONDS))
        try {
            connectionError?.let { throw it }
            assertNotNull("binder is null", binder)
            return block(IIviSecService.Stub.asInterface(binder!!))
        } finally {
            targetContext.unbindService(connection)
        }
    }

    @Test
    fun whitelistedSameSignatureCallerCanQueryState() {
        application.graphOverride = graph(setOf(testPackage))
        withService { service ->
            val state = service.state
            assertTrue("state $state out of range", state in 0..6)
            service.invalidateDeviceToken()
        }
    }

    @Test
    fun binderFailuresCarryStableWireCodes() {
        application.graphOverride = graph(setOf(testPackage))
        withService { service ->
            val signError = runCatching { service.signNonce(ByteArray(32)) }.exceptionOrNull()
            assertTrue("expected a propagated binder exception, got $signError", signError is IllegalStateException)
            assertEquals(
                SecError.NOT_PROVISIONED,
                SecError.codeOfWireMessage((signError as IllegalStateException).message),
            )

            val tokenError = runCatching { service.getDeviceToken(emptyArray()) }.exceptionOrNull()
            assertTrue(tokenError is IllegalStateException)
            assertEquals(
                SecError.NOT_PROVISIONED,
                SecError.codeOfWireMessage((tokenError as IllegalStateException).message),
            )
        }
    }

    @Test
    fun unlistedCallerIsRejectedWithCallerRejected() {
        application.graphOverride = graph(emptySet())
        withService { service ->
            val error = runCatching { service.state }.exceptionOrNull()
            assertTrue("expected SecurityException, got $error", error is SecurityException)
            assertEquals(
                SecError.CALLER_REJECTED,
                SecError.codeOfWireMessage((error as SecurityException).message),
            )
        }
    }
}
