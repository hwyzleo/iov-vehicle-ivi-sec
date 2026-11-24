package net.hwyz.iov.vehicle.ivi.sec.provisioning

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.hwyz.iov.vehicle.ivi.sec.BuildConfig
import net.hwyz.iov.vehicle.ivi.sec.R
import net.hwyz.iov.vehicle.ivi.sec.api.SecState
import net.hwyz.iov.vehicle.ivi.sec.domain.crypto.CertificateChainCodec
import net.hwyz.iov.vehicle.ivi.sec.domain.SecException
import net.hwyz.iov.vehicle.ivi.sec.domain.ProviderSnapshot
import net.hwyz.iov.vehicle.ivi.sec.secGraph
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Minimal provisioning entry (IVI-SEC-SPEC §6.1).
 *
 * Operations: create key + CSR, export the CSR through SAF or the app files directory, import the
 * certificate chain pasted as text, from SAF or from the app files directory, reopen a completed
 * identity.
 *
 * The production component is not exported. Debug builds add an exported
 * `DebugProvisioningEntry` alias (see `src/debug/AndroidManifest.xml`) so a bench device can be
 * provisioned with adb; release builds keep the provisioning surface closed.
 */
class ProvisioningActivity : ComponentActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val fileStore by lazy { ProvisioningFileStore(applicationContext) }

    private lateinit var statusView: TextView
    private lateinit var stateView: TextView
    private lateinit var csrView: TextView
    private lateinit var chainInput: EditText
    private var csrPem: String? = null

    private val createCsrFile = registerForActivityResult(
        ActivityResultContracts.CreateDocument(CSR_MIME),
    ) { uri -> uri?.let(::writeCsr) }

    private val pickChainFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let(::importChain) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildContent())
        restoreCsr()
        refresh()
        handleDebugIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDebugIntent(intent)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun buildContent(): View {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.START
            val padding = (24 * resources.displayMetrics.density).toInt()
            setPadding(padding, padding, padding, padding)
        }
        stateView = TextView(this).apply {
            textSize = 15f
            setPadding(0, 0, 0, 16)
        }
        statusView = TextView(this).apply {
            textSize = 14f
            setPadding(0, 16, 0, 24)
        }
        csrView = TextView(this).apply {
            textSize = 12f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(0, 8, 0, 16)
            visibility = View.GONE
        }
        layout.addView(stateView)
        layout.addView(button(R.string.action_refresh) { refresh() })
        layout.addView(button(R.string.action_reopen) { reopen() })
        layout.addView(button(R.string.action_create_csr) { createCsr() })
        layout.addView(button(R.string.action_export_csr) { exportCsr() })
        layout.addView(button(R.string.action_copy_csr) { copyCsr() })
        layout.addView(chainLabel())
        layout.addView(chainInputField())
        layout.addView(button(R.string.action_paste_chain) { pasteChainFromClipboard() })
        layout.addView(button(R.string.action_import_pasted) { importPastedChain() })
        layout.addView(button(R.string.action_import_chain) { importChainPicker() })
        layout.addView(button(R.string.action_import_storage) { importChainFromStorage() })
        layout.addView(statusView)
        layout.addView(csrView)
        return ScrollView(this).apply { addView(layout) }
    }

    private fun chainLabel(): TextView = TextView(this).apply {
        text = getString(R.string.chain_input_label)
        textSize = 14f
        setPadding(0, 16, 0, 8)
    }

    private fun chainInputField(): EditText = EditText(this).apply {
        chainInput = this
        hint = getString(R.string.chain_input_hint)
        textSize = 11f
        typeface = android.graphics.Typeface.MONOSPACE
        gravity = Gravity.TOP or Gravity.START
        minLines = 6
        inputType = android.text.InputType.TYPE_CLASS_TEXT or
            android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
            android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        setPadding(8, 8, 8, 8)
    }

    private fun button(label: Int, action: () -> Unit): Button = Button(this).apply {
        setText(label)
        setOnClickListener { action() }
    }

    private fun refresh() {
        runAction {
            val snapshot = withContext(Dispatchers.IO) { secGraph().facade.providerSnapshot() }
            stateView.text = render(snapshot)
        }
    }

    private fun reopen() {
        runAction {
            val state = withContext(Dispatchers.IO) { secGraph().facade.reopen() }
            statusView.text = "Reopened: ${SecState.nameOf(state)}"
            refresh()
        }
    }

    private fun createCsr() {
        runAction {
            val result = withContext(Dispatchers.IO) { secGraph().facade.requestCsr() }
            showCsr(result.csrPem)
            val saved = withContext(Dispatchers.IO) { fileStore.writeCsr(result.csrPem) }
            statusView.text = if (saved.isEmpty()) {
                getString(R.string.csr_ready) + " (CN=${result.hsmUid}, storage write failed)"
            } else {
                getString(R.string.csr_saved_to, saved.first().absolutePath) +
                    " (CN=${result.hsmUid})"
            }
            refresh()
        }
    }

    /** Restores the last CSR so a process restart or a bench revisit still shows it. */
    private fun restoreCsr() {
        scope.launch {
            val pem = withContext(Dispatchers.IO) { fileStore.readCsr() }
            if (pem != null) showCsr(pem)
        }
    }

    private fun showCsr(pem: String) {
        csrPem = pem
        csrView.text = pem
        csrView.visibility = View.VISIBLE
    }

    private fun copyCsr() {
        val cached = csrPem
        if (cached != null) {
            copyToClipboard(cached)
            return
        }
        runAction {
            val pem = withContext(Dispatchers.IO) { fileStore.readCsr() }
            if (pem == null) {
                statusView.text = getString(R.string.csr_missing)
            } else {
                showCsr(pem)
                copyToClipboard(pem)
            }
        }
    }

    private fun copyToClipboard(pem: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("ivi-sec-csr", pem))
        statusView.text = getString(R.string.csr_copied)
    }

    private fun exportCsr() {
        val pem = csrPem
        if (pem == null) {
            statusView.text = getString(R.string.csr_missing)
            return
        }
        try {
            createCsrFile.launch(ProvisioningFileStore.CSR_FILE_NAME)
        } catch (error: ActivityNotFoundException) {
            // No usable document provider (automotive images often ship without one).
            showCsr(pem)
            statusView.text = getString(
                R.string.csr_export_unavailable,
                fileStore.csrTargets().first().absolutePath,
            )
        }
    }

    private fun importChainPicker() {
        pickChainFile.launch(arrayOf(CSR_MIME, "application/x-pem-file", "text/plain", "*/*"))
    }

    /** Fills the text field from the clipboard: typing a PEM bundle on a tablet is impractical. */
    private fun pasteChainFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(this)
            ?.toString()
            ?.trim()
        if (text.isNullOrEmpty()) {
            statusView.text = getString(R.string.chain_clipboard_empty)
            return
        }
        chainInput.setText(text)
        chainInput.setSelection(0)
        statusView.text = getString(R.string.chain_pasted, text.length)
    }

    /** Manual channel: the operator pastes the PKI chain PEM directly into the provisioning UI. */
    private fun importPastedChain() {
        val text = chainInput.text?.toString()?.trim().orEmpty()
        if (text.isEmpty()) {
            statusView.text = getString(R.string.chain_input_empty)
            return
        }
        importChainBytes(text.toByteArray(Charsets.US_ASCII))
    }

    private fun writeCsr(uri: Uri) {
        val pem = csrPem ?: return
        runAction {
            withContext(Dispatchers.IO) {
                requireNotNull(contentResolver.openOutputStream(uri)) { "cannot open $uri" }.use { stream ->
                    stream.write(pem.toByteArray(Charsets.US_ASCII))
                }
            }
            statusView.text = "CSR exported"
        }
    }

    private fun importChain(uri: Uri) {
        runAction {
            val bytes = withContext(Dispatchers.IO) {
                requireNotNull(contentResolver.openInputStream(uri)) { "cannot open $uri" }
                    .use { it.readBytes() }
            }
            importChainBytes(bytes)
        }
    }

    /** Engineering channel: reads the chain file written by `adb push` / `run-as`. */
    private fun importChainFromStorage() {
        runAction {
            val bytes = withContext(Dispatchers.IO) {
                val file = fileStore.findChainFile()
                    ?: error(
                        getString(R.string.chain_file_missing) + " " +
                            fileStore.chainTargets().joinToString { it.absolutePath },
                    )
                file.readBytes()
            }
            importChainBytes(bytes)
        }
    }

    /** Engineering channel: the chain comes in the launch intent, so no file access is needed. */
    private fun importChainFromIntent(intent: Intent): Boolean {
        val pem = intent.getStringExtra(EXTRA_CHAIN_PEM) ?: intent.getStringExtra("chain")
        val encoded = intent.getStringExtra(EXTRA_CHAIN_BASE64) ?: intent.getStringExtra("chainBase64")
        val bytes = when {
            pem != null -> pem.toByteArray(Charsets.US_ASCII)
            encoded != null -> Base64.decode(encoded, Base64.NO_WRAP)
            else -> return false
        }
        importChainBytes(bytes)
        return true
    }

    private fun importChainBytes(bytes: ByteArray) {
        runAction {
            val imported = withContext(Dispatchers.IO) {
                require(bytes.size <= MAX_CHAIN_BYTES) {
                    getString(R.string.chain_too_large, MAX_CHAIN_BYTES)
                }
                val chain = CertificateChainCodec.parse(bytes)
                secGraph().facade.importCertificateChain(chain.map { it.encoded })
            }
            statusView.text = getString(R.string.chain_imported, imported.subject)
            refresh()
        }
    }

    /** Debug entry operations, so a bench device can be provisioned without UI automation. */
    private fun handleDebugIntent(intent: Intent?) {
        if (!BuildConfig.DEBUG || intent == null) return
        val operation = intent.getStringExtra(EXTRA_OPERATION) ?: intent.getStringExtra("op")
        when (operation) {
            OPERATION_CREATE_CSR -> createCsr()
            OPERATION_IMPORT_CHAIN -> if (!importChainFromIntent(intent)) importChainFromStorage()
            OPERATION_REOPEN -> reopen()
        }
    }

    private fun runAction(block: suspend () -> Unit) {
        scope.launch {
            try {
                block()
            } catch (error: SecException) {
                statusView.text = "${error.error.name}: ${error.reason ?: ""}"
            } catch (error: Exception) {
                statusView.text = "Error: ${error.javaClass.simpleName}: ${error.message ?: ""}"
            }
        }
    }

    private fun render(snapshot: ProviderSnapshot): String {
        val formatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val notAfter = if (snapshot.notAfterEpochMillis > 0) {
            formatter.format(Date(snapshot.notAfterEpochMillis))
        } else {
            "-"
        }
        return buildString {
            appendLine("${getString(R.string.state_label)}: ${SecState.nameOf(snapshot.state)}")
            appendLine("${getString(R.string.device_id_label)}: ${snapshot.deviceId ?: "-"}")
            appendLine("${getString(R.string.certificate_label)}: ${snapshot.certSn ?: "-"} / $notAfter")
            append("last_reason_code: ${snapshot.lastReasonCode}")
        }
    }

    companion object {
        const val EXTRA_OPERATION = "net.hwyz.iov.vehicle.ivi.sec.extra.OPERATION"
        const val EXTRA_CHAIN_PEM = "net.hwyz.iov.vehicle.ivi.sec.extra.CHAIN_PEM"
        const val EXTRA_CHAIN_BASE64 = "net.hwyz.iov.vehicle.ivi.sec.extra.CHAIN_BASE64"
        const val OPERATION_CREATE_CSR = "createCsr"
        const val OPERATION_IMPORT_CHAIN = "importChain"
        const val OPERATION_REOPEN = "reopen"
        const val CSR_MIME = "application/pkcs10"
        private const val MAX_CHAIN_BYTES = 64 * 1024
    }
}
