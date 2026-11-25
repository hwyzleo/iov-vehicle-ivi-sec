# iov-vehicle-ivi-sec

Vehicle-side device identity service for IVI (Kotlin/Android). The service is the single holder of
the device private key and certificate chain, the single device proof producer and the single caller
of the SEC-CIAM device identity grant.

Design baseline: `IVI-SEC-SPEC设计` 1.0 (`IVI-SEC-DSN-CR-001`).

## Modules

| Module | Type | Responsibility |
|--------|------|----------------|
| `sec-api` | Android library (AAR) | AIDL `IIviSecService`, `CertificateInfo` / `DeviceToken` parcelables, state/error constants, permission and provider contract |
| `sec-domain` | Kotlin/JVM | State machine, PKCS#10 CSR, certificate chain validation, token single flight, failure classification, admission policy, rate limits, audit ring, use-case facade |
| `sec-data` | Android library | AndroidKeyStore key custody, DataStore metadata, OkHttp SEC-CIAM client, caller identity/signature resolution, device serial, logcat diagnostics |
| `app` | Android application | Service, read-only provider, provisioning activity, manifest declarations, dependency wiring |

Dependency direction: `app` → `sec-data`/`sec-api` → `sec-domain`; `sec-domain` has no Android API.

## Cross-application contract

- Service: exported, guarded by signature permission
  `net.hwyz.iov.vehicle.ivi.sec.permission.USE_DEVICE_IDENTITY`
  (`SERVICE_ACTION`, `SERVICE_CLASS`, `SERVICE_PACKAGE` in `SecContract`).
- Provider: exported, read-only, guarded by signature permission
  `net.hwyz.iov.vehicle.ivi.sec.permission.READ_STATE`; authority
  `net.hwyz.iov.vehicle.ivi.sec.state`; columns `state, device_id, cert_sn, not_after,
  last_reason_code, updated_at`. It never exposes tokens, signatures or key material.
- Binder failures use public `IllegalStateException` (and `SecurityException` for caller rejection)
  whose message is `IVI_SEC:<code>:<NAME>`; `SecError.codeOfWireMessage(message)` decodes it.
  `android.app.ServiceSpecificException` is not part of the public SDK, so it cannot be used.

## Provisioning

1. Operator opens the provisioning activity (not exported in release; debug builds expose
   `DebugProvisioningEntry`), creates the EC P-256 key in AndroidKeyStore and exports the PKCS#10 CSR.
   The CSR follows the TBOX device profile: `CN=<hsm_uid>, OU=IVI-TSP, O=OpenIOV, C=CN`,
   `SAN=urn:ecu-uid:<hsm_uid>`, requested `KU=digitalSignature+keyAgreement`, `EKU=clientAuth`.
   `hsm_uid` is the same identity value used by the TBOX; on devices where the vendor does not expose
   it, the deployment supplies a provisioned value (`HSM_UID` BuildConfig, currently a mock).
2. The PKI channel signs the CSR and returns the certificate chain.
3. Operator imports the chain; the service validates chain order, signature and that the leaf public
   key matches the local key, then stores the metadata as `ISSUED_PENDING_CLOUD`.
4. The first successful device token issuance moves the state to `ACTIVE`.

The provisioning UI accepts the chain through three channels: the SAF file picker, a file pushed into
`app/build`-independent app storage (`ivi-sec-device-chain.pem` / `.der`), and a text field that can be
filled by pasting from the clipboard. All three feed the same `CertificateChainCodec.parse`:

- **PEM bundle, leaf first**: one `-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----` block per
  certificate, ordered leaf → intermediate(s) → (optional) root. Comments, blank lines and unrelated
  text between blocks are ignored, so a PKI response file can be pasted as-is.
- **A single DER certificate** (no PEM armour) is also accepted, but then it must be the leaf and no
  intermediate may be required.
- Not accepted: the CSR (`BEGIN CERTIFICATE REQUEST`), PKCS#7/`.p7b` containers, bare base64 without
  the PEM header, a root-first or otherwise unordered chain, and a leaf whose public key does not
  match the key in AndroidKeyStore. Import requires state `PROVISIONING`, so create the CSR first.

The `--es chainBase64` intent extra carries base64 of the PEM (or DER) file bytes.

### Engineering provisioning over adb (debug builds)

Debug builds write the CSR to the app files directories and expose an exported alias, so the flow
works on images without DocumentsUI:

```bash
adb shell am start -n net.hwyz.iov.vehicle.ivi.sec/.provisioning.DebugProvisioningEntry \
  --es op createCsr
adb pull /sdcard/Android/data/net.hwyz.iov.vehicle.ivi.sec/files/ivi-sec-device.csr
# Sign the CSR externally, then import the chain without any file access:
CHAIN_B64=$(base64 < ivi-sec-device-chain.pem | tr -d '\n')
adb shell am start -n net.hwyz.iov.vehicle.ivi.sec/.provisioning.DebugProvisioningEntry \
  --es op importChain --es chainBase64 "$CHAIN_B64"
adb root   # READ_STATE is signature protected; use root on a bench image to query it
adb shell content query --uri content://net.hwyz.iov.vehicle.ivi.sec.state/state
```

The CSR is also displayed inside the activity as selectable text with a **Copy CSR** button, and it is
restored from the app files after a restart. Interactive export through the system file manager is
optional and fails gracefully on images without a document provider (automotive images often have
none).

The CSR path above is for a single-user device. On multi-user automotive images the app data lives
under `/data/user/<userId>/...`, which the shell cannot read; use `adb root` (engineering image) or
pull through the app files directory with the appropriate user path. The import itself needs no file
access because the chain travels in the intent.

If you prefer files, put the chain into `ivi-sec-device-chain.pem` in the app files directory and run
the same `--es op importChain` without `chainBase64`. A `run-as` copy works on user 0; on multi-user
images use root plus `chown`/`restorecon` because a root-created file has the wrong SELinux label.

Release builds keep the activity unexported; the production launch path is tracked in
`IVI-SEC-DSN-CR-001` §19.5.

## Build and test

```bash
./gradlew :sec-domain:test :sec-data:testDebugUnitTest :app:testDebugUnitTest
./gradlew :app:assembleDebug
./gradlew :app:connectedDebugAndroidTest   # requires a device/emulator
```

Instrumentation coverage: real AndroidKeyStore key generation, CSR verification, certificate import,
signature verification, provider read-only/contract checks, permission declarations and binder
failure codes. External end-to-end (real SGW/SEC-CIAM/SEC-VIAM/PKI), cross-signature caller rejection
and TEE hardware evidence are not executable in this repository and stay blocked until the external
dependencies in `IVI-SEC-DSN-CR-001` §14 are delivered.

## Configuration

Deployment values are `BuildConfig` fields in `app/build.gradle.kts` (`SGW_BASE_URL`,
`CIAM_CLIENT_ID`, `DEVICE_KEY_ALIAS`, `DEVICE_SCOPES`, `CALLER_WHITELIST`, `HSM_UID`, `DEVICE_SN`).
Security policy defaults
(nonce bounds, renewal windows, rate limits, audit capacity) live in `SecConfig`.

Two deployment identities are separate on purpose (IVI-SEC-DSN-CR-002):

- `HSM_UID` — the security chip identity used only for the certificate: CSR `CN=<hsm_uid>`,
  `SAN=urn:ecu-uid:<hsm_uid>`, PKI/VIAM subject. Currently the mock
  `00000005AA0000000000000000000001`; it must be replaced per device before production (two devices
  sharing one UID collide in PKI/VIAM registration).
- `DEVICE_SN` — the device serial sent as the CIAM `device_id` claim. Currently the mock
  `00000005AA00000001`; it must be injected per vehicle by the line (`-PdeviceSn=...` overrides it)
  and **must equal the device subject registered in VIAM**, otherwise CIAM rejects the grant.

`DeviceSerialResolver` owns the resolution order: `DEVICE_SN` → platform read only serial
(`Build.getSerial()` → `Build.SERIAL`) → none, in which case the token request fails closed. Never
substitute `hsm_uid`, `Settings.Secure`, VIN, the client id or a random UUID.

The debug build appends the instrumentation package to `CALLER_WHITELIST`; release builds keep only
the registered IVI callers.

## Security notes

- Private keys are generated in AndroidKeyStore and are not exportable; no API returns private key
  material.
- Device tokens, nonces and signatures stay in memory and never reach DataStore or logs; the log sink
  drops a fixed sensitive-key denylist.
- Every failure path is fail-closed with a stable error code; negative token results are not cached.
- Token issuance is single-flight and limited to 12/minute per device; signing is limited to
  30/minute per caller.
