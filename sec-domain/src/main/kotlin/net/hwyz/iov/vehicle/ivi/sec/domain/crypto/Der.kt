package net.hwyz.iov.vehicle.ivi.sec.domain.crypto

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * Minimal DER encoder for PKCS#10 (IVI-SEC-SPEC D-008).
 *
 * Only the primitives the certification request needs are implemented; the device never parses
 * arbitrary ASN.1 from the network.
 */
internal object Der {

    const val TAG_BOOLEAN = 0x01
    const val TAG_INTEGER = 0x02
    const val TAG_BIT_STRING = 0x03
    const val TAG_OID = 0x06
    const val TAG_UTF8_STRING = 0x0C
    const val TAG_OCTET_STRING = 0x04
    const val TAG_SEQUENCE = 0x30
    const val TAG_SET = 0x31
    const val TAG_CONTEXT_0_CONSTRUCTED = 0xA0

    fun tlv(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        out.write(encodeLength(content.size))
        out.write(content)
        return out.toByteArray()
    }

    fun sequence(vararg items: ByteArray): ByteArray = tlv(TAG_SEQUENCE, concat(items))

    fun set(vararg items: ByteArray): ByteArray = tlv(TAG_SET, concat(items))

    fun integer(value: Int): ByteArray {
        require(value >= 0) { "negative integer is not supported" }
        var length = 1
        while (length < 4 && (value ushr (length * 8)) != 0) length++
        val content = ByteArray(length)
        for (i in 0 until length) {
            content[i] = (value ushr ((length - 1 - i) * 8)).toByte()
        }
        // Keep the value positive: a leading high bit needs a 0x00 pad.
        return if (content[0].toInt() and 0x80 != 0) tlv(TAG_INTEGER, byteArrayOf(0) + content)
        else tlv(TAG_INTEGER, content)
    }

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map {
            requireNotNull(it.toIntOrNull()) { "invalid OID arc '$it'" }
        }
        require(arcs.size >= 2) { "OID needs at least two arcs" }
        require(arcs[0] in 0..2) { "invalid first OID arc" }
        require(arcs[1] in 0..39 || arcs[0] == 2) { "invalid second OID arc" }
        val content = ByteArrayOutputStream()
        writeBase128(content, arcs[0] * 40L + arcs[1])
        for (index in 2 until arcs.size) {
            require(arcs[index] >= 0) { "negative OID arc" }
            writeBase128(content, arcs[index].toLong())
        }
        return tlv(TAG_OID, content.toByteArray())
    }

    fun utf8(value: String): ByteArray = tlv(TAG_UTF8_STRING, value.toByteArray(StandardCharsets.UTF_8))

    fun octetString(value: ByteArray): ByteArray = tlv(TAG_OCTET_STRING, value)

    fun bitString(value: ByteArray): ByteArray = tlv(TAG_BIT_STRING, byteArrayOf(0) + value)

    fun contextConstructed(tagNumber: Int, content: ByteArray): ByteArray =
        tlv(TAG_CONTEXT_0_CONSTRUCTED + tagNumber, content)

    private fun writeBase128(out: ByteArrayOutputStream, value: Long) {
        require(value >= 0) { "negative base-128 value" }
        var remaining = value
        val buffer = ArrayList<Byte>()
        do {
            buffer.add(0, (remaining and 0x7F).toByte())
            remaining = remaining ushr 7
        } while (remaining > 0)
        for (index in buffer.indices) {
            val last = index == buffer.lastIndex
            val byte = if (last) buffer[index].toInt() else buffer[index].toInt() or 0x80
            out.write(byte)
        }
    }

    private fun encodeLength(length: Int): ByteArray {
        require(length >= 0) { "negative length" }
        if (length < 0x80) return byteArrayOf(length.toByte())
        var remaining = length
        val bytes = ArrayList<Byte>()
        while (remaining > 0) {
            bytes.add(0, (remaining and 0xFF).toByte())
            remaining = remaining ushr 8
        }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    private fun concat(items: Array<out ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        items.forEach(out::write)
        return out.toByteArray()
    }
}
