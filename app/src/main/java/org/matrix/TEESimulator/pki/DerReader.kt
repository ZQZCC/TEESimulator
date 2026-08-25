package org.matrix.TEESimulator.pki

import java.math.BigInteger

/** A parsed DER TLV. [tagNo] is the full tag number (works for universal and context tags). */
class DerTlv(
    val tagClass: Int, // 0=universal, 1=application, 2=context, 3=private
    val constructed: Boolean,
    val tagNo: Int,
    val value: ByteArray, // content octets
    val encoded: ByteArray, // the complete TLV
) {
    val isContext: Boolean
        get() = tagClass == 2

    /** INTEGER content as a non-negative value (mirrors BouncyCastle's positiveValue). */
    fun positiveInt(): BigInteger = BigInteger(1, value)

    /** For a single-element EXPLICIT tag, the wrapped element. */
    fun inner(): DerTlv = DerReader.readOne(value)
}

/** Minimal DER (X.690) reader: just enough to walk certificates and attestation records. */
object DerReader {

    /** Reads one TLV at [offset]; returns it and the offset immediately after it. */
    fun read(bytes: ByteArray, offset: Int): Pair<DerTlv, Int> {
        var p = offset
        val first = bytes[p++].toInt() and 0xff
        val tagClass = (first ushr 6) and 0x03
        val constructed = (first and 0x20) != 0
        var tagNo = first and 0x1f
        if (tagNo == 0x1f) {
            tagNo = 0
            while (true) {
                val b = bytes[p++].toInt() and 0xff
                tagNo = (tagNo shl 7) or (b and 0x7f)
                if (b and 0x80 == 0) break
            }
        }
        var length = bytes[p++].toInt() and 0xff
        if (length and 0x80 != 0) {
            val count = length and 0x7f
            length = 0
            repeat(count) { length = (length shl 8) or (bytes[p++].toInt() and 0xff) }
        }
        val value = bytes.copyOfRange(p, p + length)
        val encoded = bytes.copyOfRange(offset, p + length)
        return DerTlv(tagClass, constructed, tagNo, value, encoded) to (p + length)
    }

    /** Reads the single TLV that spans all of [bytes]. */
    fun readOne(bytes: ByteArray): DerTlv = read(bytes, 0).first

    /** Splits a constructed value into its child TLVs. */
    fun children(value: ByteArray): List<DerTlv> {
        val result = ArrayList<DerTlv>()
        var p = 0
        while (p < value.size) {
            val (tlv, next) = read(value, p)
            result.add(tlv)
            p = next
        }
        return result
    }
}
