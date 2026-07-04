package org.matrix.TEESimulator.util

/**
 * Trims leading and trailing whitespace from each line in a multi-line string. This is useful for
 * cleaning up PEM-formatted keys and certificates.
 *
 * @return A new string with each line individually trimmed.
 */
fun String.trimLines(): String = this.trim().lines().joinToString("\n") { it.trim() }

/**
 * Converts a ByteArray to its hexadecimal string representation.
 *
 * @return The lowercase hex string.
 */
fun ByteArray.toHex(): String {
    val digits = "0123456789abcdef"
    val result = StringBuilder(size * 2)
    for (byte in this) {
        val value = byte.toInt() and 0xff
        result.append(digits[value ushr 4])
        result.append(digits[value and 0x0f])
    }
    return result.toString()
}

fun String.hexToByteArrayOrNull(expectedSize: Int): ByteArray? {
    if (length != expectedSize * 2) return null
    val result = ByteArray(expectedSize)
    for (i in 0 until expectedSize) {
        val high = Character.digit(this[i * 2], 16)
        val low = Character.digit(this[i * 2 + 1], 16)
        if (high < 0 || low < 0) return null
        result[i] = ((high shl 4) or low).toByte()
    }
    return result
}
