package net.hwyz.iov.vehicle.ivi.sec

import android.content.Context
import net.hwyz.iov.vehicle.ivi.sec.data.caller.AndroidCallerIdentityProvider
import net.hwyz.iov.vehicle.ivi.sec.data.cloud.OkHttpDeviceTokenClient
import net.hwyz.iov.vehicle.ivi.sec.data.keystore.AndroidKeyStoreDeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.data.log.AndroidDiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.data.platform.AndroidDeviceSerialProvider
import net.hwyz.iov.vehicle.ivi.sec.data.platform.DeviceSerialResolver
import net.hwyz.iov.vehicle.ivi.sec.data.store.DataStoreSecMetaStore
import net.hwyz.iov.vehicle.ivi.sec.domain.IviSecFacade
import net.hwyz.iov.vehicle.ivi.sec.domain.admission.CallerPolicy
import net.hwyz.iov.vehicle.ivi.sec.domain.admission.RateLimiter
import net.hwyz.iov.vehicle.ivi.sec.domain.audit.AuditRingBuffer
import net.hwyz.iov.vehicle.ivi.sec.domain.clock.Clock
import net.hwyz.iov.vehicle.ivi.sec.domain.config.SecConfig
import net.hwyz.iov.vehicle.ivi.sec.domain.port.CallerVerifier
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceKeyPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DeviceTokenPort
import net.hwyz.iov.vehicle.ivi.sec.domain.port.DiagnosticsLogger
import net.hwyz.iov.vehicle.ivi.sec.domain.port.SecMetaStore
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceScopes
import net.hwyz.iov.vehicle.ivi.sec.domain.token.DeviceTokenCoordinator
import net.hwyz.iov.vehicle.ivi.sec.domain.token.KeystoreProofGenerator
import net.hwyz.iov.vehicle.ivi.sec.domain.token.TokenConfig

/**
 * Manual dependency wiring (IVI-SEC-SPEC D-013: the app module only assembles Android components).
 *
 * Production values come from BuildConfig; security policy defaults come from [SecConfig]. Every
 * collaborator can be replaced in tests without touching the production graph.
 */
class SecGraph(
    context: Context,
    val deviceKeyPort: DeviceKeyPort = AndroidKeyStoreDeviceKeyPort(),
    val metaStore: SecMetaStore = DataStoreSecMetaStore.create(context.applicationContext),
    callerVerifier: CallerVerifier = AndroidCallerIdentityProvider(context.applicationContext),
    /**
     * CIAM `device_id` claim (IVI-SEC-DSN-CR-002 D-003): deploy supplied SN first, platform read only
     * serial second, otherwise null so the token request fails closed.
     *
     * BLK-4: the device serial reader needs no context any more (the Settings fallback is gone).
     */
    private val deviceIdProvider: () -> String? = {
        DeviceSerialResolver.resolve(
            deployValue = BuildConfig.DEVICE_SN,
            platformValue = { AndroidDeviceSerialProvider().deviceId() },
        ).value
    },
    tokenClient: DeviceTokenPort = OkHttpDeviceTokenClient(
        baseUrl = BuildConfig.SGW_BASE_URL,
        clientId = BuildConfig.CIAM_CLIENT_ID,
    ),
    val config: SecConfig = SecConfig(
        keyAlias = BuildConfig.DEVICE_KEY_ALIAS,
        hsmUid = BuildConfig.HSM_UID,
        deviceScopes = BuildConfig.DEVICE_SCOPES
            .split(' ')
            .map { it.trim() }
            .filter { it.isNotEmpty() },
    ),
    callerWhitelist: Set<String> = BuildConfig.CALLER_WHITELIST
        .split(',')
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .toSet(),
    val logger: DiagnosticsLogger = AndroidDiagnosticsLogger(),
    val clock: Clock = Clock.System,
) {
    val audit = AuditRingBuffer(config.auditCapacity)

    private val rateLimiter = RateLimiter(
        clock = clock,
        signPerCallerPerMinute = config.signPerCallerPerMinute,
        tokenPerDevicePerMinute = config.tokenPerDevicePerMinute,
        windowMillis = config.rateWindowMillis,
    )

    private val tokenCoordinator = DeviceTokenCoordinator(
        port = tokenClient,
        proofGenerator = KeystoreProofGenerator(
            keys = deviceKeyPort,
            alias = config.keyAlias,
            deviceId = deviceIdProvider(),
        ),
        scopes = DeviceScopes(config.deviceScopes),
        config = TokenConfig(),
        clock = clock,
        logger = logger,
        issuePermit = rateLimiter::tryAcquireToken,
    )

    val facade: IviSecFacade = IviSecFacade(
        keys = deviceKeyPort,
        metaStore = metaStore,
        tokens = tokenCoordinator,
        deviceIdProvider = deviceIdProvider,
        callerVerifier = callerVerifier,
        callerPolicy = CallerPolicy(callerWhitelist),
        rateLimiter = rateLimiter,
        audit = audit,
        clock = clock,
        config = config,
        logger = logger,
    )
}
