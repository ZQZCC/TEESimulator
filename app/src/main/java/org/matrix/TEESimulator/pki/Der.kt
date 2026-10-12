package org.matrix.TEESimulator.pki

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/**
 * Minimal DER (X.690) writer. Every encoding here is verified byte-identical to the corresponding
 * BouncyCastle output (see the JVM cross-check in the project's tooling). Elements are represented
 * as raw `ByteArray` fragments and composed by concatenation.
 */
object Der {

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (p in parts) out.write(p)
        return out.toByteArray()
    }

    fun concat(parts: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        for (p in parts) out.write(p)
        return out.toByteArray()
    }

    /** DER definite-form length octets. */
    fun len(length: Int): ByteArray {
        if (length < 0x80) return byteArrayOf(length.toByte())
        val bytes = ArrayList<Int>()
        var v = length
        while (v > 0) {
            bytes.add(0, v and 0xff)
            v = v ushr 8
        }
        val out = ByteArrayOutputStream()
        out.write(0x80 or bytes.size)
        for (b in bytes) out.write(b)
        return out.toByteArray()
    }

    /** Tag-length-value with a single-octet tag. */
    fun tlv(tag: Int, value: ByteArray): ByteArray =
        concat(byteArrayOf(tag.toByte()), len(value.size), value)

    fun integer(v: Long): ByteArray = tlv(0x02, BigInteger.valueOf(v).toByteArray())

    fun integer(v: BigInteger): ByteArray = tlv(0x02, v.toByteArray())

    fun enumerated(v: Long): ByteArray = tlv(0x0a, BigInteger.valueOf(v).toByteArray())

    fun bool(b: Boolean): ByteArray = tlv(0x01, byteArrayOf((if (b) 0xff else 0x00).toByte()))

    fun nullValue(): ByteArray = byteArrayOf(0x05, 0x00)

    fun octetString(value: ByteArray): ByteArray = tlv(0x04, value)

    /** BIT STRING with zero unused bits (e.g. a certificate signature). */
    fun bitStringNoUnused(value: ByteArray): ByteArray = tlv(0x03, concat(byteArrayOf(0x00), value))

    fun utf8String(s: String): ByteArray = tlv(0x0c, s.toByteArray(Charsets.UTF_8))

    fun oid(oid: String): ByteArray {
        val parts = oid.split('.').map { it.toLong() }
        val body = ByteArrayOutputStream()
        body.write((parts[0] * 40 + parts[1]).toInt())
        for (i in 2 until parts.size) writeBase128(body, parts[i])
        return tlv(0x06, body.toByteArray())
    }

    private fun writeBase128(out: ByteArrayOutputStream, value: Long) {
        val bytes = ArrayList<Int>()
        bytes.add((value and 0x7f).toInt())
        var v = value ushr 7
        while (v > 0) {
            bytes.add(0, ((v and 0x7f) or 0x80).toInt())
            v = v ushr 7
        }
        for (b in bytes) out.write(b)
    }

    fun sequence(vararg elements: ByteArray): ByteArray = tlv(0x30, concat(*elements))

    fun sequence(elements: List<ByteArray>): ByteArray = tlv(0x30, concat(elements))

    /**
     * DER SET OF: element encodings are emitted in ascending order, compared as octet strings with
     * the shorter one padded at its trailing end with zero octets (X.690 clause 11.6).
     */
    fun set(elements: List<ByteArray>): ByteArray =
        tlv(0x31, concat(elements.sortedWith(SET_OF_COMPARATOR)))

    val SET_OF_COMPARATOR =
        Comparator<ByteArray> { a, b ->
            val n = maxOf(a.size, b.size)
            for (i in 0 until n) {
                val ai = if (i < a.size) a[i].toInt() and 0xff else 0
                val bi = if (i < b.size) b[i].toInt() and 0xff else 0
                if (ai != bi) return@Comparator ai - bi
            }
            0
        }

    /** Context-class tag octet(s); uses high-tag-number form when [tagNo] >= 31. */
    fun contextTag(tagNo: Int, constructed: Boolean): ByteArray {
        val first = 0x80 or (if (constructed) 0x20 else 0)
        if (tagNo < 0x1f) return byteArrayOf((first or tagNo).toByte())
        val bytes = ArrayList<Int>()
        bytes.add(tagNo and 0x7f)
        var v = tagNo ushr 7
        while (v > 0) {
            bytes.add(0, (v and 0x7f) or 0x80)
            v = v ushr 7
        }
        val out = ByteArrayOutputStream()
        out.write(first or 0x1f)
        for (b in bytes) out.write(b)
        return out.toByteArray()
    }

    /** `[tagNo] EXPLICIT`: a constructed context tag wrapping the full encoding of [content]. */
    fun explicit(tagNo: Int, content: ByteArray): ByteArray =
        concat(contextTag(tagNo, true), len(content.size), content)
}
