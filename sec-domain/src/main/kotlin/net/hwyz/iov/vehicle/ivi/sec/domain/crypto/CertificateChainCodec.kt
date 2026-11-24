package net.hwyz.iov.vehicle.ivi.sec.domain.crypto

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Certificate chain parsing and validation (IVI-SEC-SPEC US-002).
 *
 * Accepts PEM bundles produced by the PKI channel and raw DER. The chain order is leaf first, which
 * is also the order the platform keystore expects.
 */
object CertificateChainCodec {

    private const val PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val PEM_END = "-----END CERTIFICATE-----"

    fun parse(bytes: ByteArray): List<X509Certificate> {
        require(bytes.isNotEmpty()) { "certificate input is empty" }
        val text = String(bytes, Charsets.US_ASCII)
        if (text.contains(PEM_BEGIN)) {
            return parsePem(text)
        }
        return parseDerList(listOf(bytes))
    }

    fun parseDerList(chainDer: List<ByteArray>): List<X509Certificate> {
        require(chainDer.isNotEmpty()) { "certificate chain is empty" }
        val factory = CertificateFactory.getInstance("X.509")
        return chainDer.mapIndexed { index, der ->
            require(der.isNotEmpty()) { "certificate #$index is empty" }
            runCatching { factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate }
                .getOrElse { throw IllegalArgumentException("certificate #$index is not a valid X.509 DER", it) }
        }
    }

    private fun parsePem(text: String): List<X509Certificate> {
        val blocks = mutableListOf<ByteArray>()
        var cursor = text.indexOf(PEM_BEGIN)
        while (cursor >= 0) {
            val bodyStart = cursor + PEM_BEGIN.length
            val bodyEnd = text.indexOf(PEM_END, bodyStart)
            require(bodyEnd > bodyStart) { "unterminated PEM certificate block" }
            val body = text.substring(bodyStart, bodyEnd).filterNot { it.isWhitespace() }
            require(body.isNotEmpty()) { "empty PEM certificate block" }
            blocks += runCatching { Base64.getDecoder().decode(body) }
                .getOrElse { throw IllegalArgumentException("invalid base64 in PEM certificate block", it) }
            cursor = text.indexOf(PEM_BEGIN, bodyEnd + PEM_END.length)
        }
        require(blocks.isNotEmpty()) { "no PEM certificate block found" }
        return parseDerList(blocks)
    }

    /** True when every non-root certificate is directly signed by the next one in the chain. */
    fun isChainOrdered(chain: List<X509Certificate>): Boolean {
        if (chain.isEmpty()) return false
        for (index in 0 until chain.size - 1) {
            val child = chain[index]
            val issuer = chain[index + 1]
            if (child.issuerX500Principal != issuer.subjectX500Principal) return false
            val verified = runCatching {
                child.verify(issuer.publicKey)
            }.isSuccess
            if (!verified) return false
        }
        return true
    }

    fun fingerprintSha256Hex(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
        return digest.joinToString(separator = "") { "%02X".format(it) }
    }

    fun toPem(chainDer: List<ByteArray>): String = buildString {
        val encoder = Base64.getMimeEncoder(64, "\n".toByteArray())
        chainDer.forEach { der ->
            append(PEM_BEGIN).append('\n')
            append(encoder.encodeToString(der)).append('\n')
            append(PEM_END).append('\n')
        }
    }
}
