package net.hwyz.iov.vehicle.ivi.sec.provisioning

import android.content.Context
import java.io.File

/**
 * File based provisioning channel used by engineering builds and the line/bench tooling.
 *
 * It does not depend on a documents provider (SAF): the CSR is written to the app internal and
 * external files directories, and the PKI chain is read from the same places. Debug builds can thus
 * be driven entirely with `adb pull` / `adb push` / `run-as`.
 */
class ProvisioningFileStore(private val context: Context) {

    /** Writes the CSR PEM to every writable target and returns the files that were written. */
    fun writeCsr(pem: String): List<File> {
        val bytes = pem.toByteArray(Charsets.US_ASCII)
        return writeTargets(CSR_FILE_NAME).mapNotNull { target ->
            runCatching {
                target.parentFile?.mkdirs()
                target.writeBytes(bytes)
                target
            }.getOrNull()
        }
    }

    /** Last CSR written by this app, used to restore the provisioning UI. */
    fun readCsr(): String? = writeTargets(CSR_FILE_NAME)
        .firstOrNull { it.isFile }
        ?.let { runCatching { it.readText() }.getOrNull() }
        ?.takeIf { it.startsWith("-----BEGIN CERTIFICATE REQUEST-----") }

    /** First existing chain file, external directory first, then internal. */
    fun findChainFile(): File? = chainTargets().firstOrNull { it.isFile }

    fun chainTargets(): List<File> = buildList {
        context.getExternalFilesDir(null)?.let { directory ->
            add(File(directory, CHAIN_PEM_FILE))
            add(File(directory, CHAIN_DER_FILE))
        }
        add(File(context.filesDir, CHAIN_PEM_FILE))
        add(File(context.filesDir, CHAIN_DER_FILE))
    }

    fun csrTargets(): List<File> = writeTargets(CSR_FILE_NAME)

    private fun writeTargets(name: String): List<File> = buildList {
        add(File(context.filesDir, name))
        context.getExternalFilesDir(null)?.let { add(File(it, name)) }
    }

    companion object {
        const val CSR_FILE_NAME = "ivi-sec-device.csr"
        const val CHAIN_PEM_FILE = "ivi-sec-device-chain.pem"
        const val CHAIN_DER_FILE = "ivi-sec-device-chain.der"
    }
}
