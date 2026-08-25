package org.matrix.TEESimulator.pki

import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Golden-vector regression tests for [Der] / [DerReader].
 *
 * Every expected byte string here was produced by BouncyCastle 1.85 — the library this code
 * replaced — and is frozen so future edits to the DER writer/reader cannot silently drift from
 * standard DER. (Regenerate with the JVM cross-check tooling if the encoding intentionally changes.)
 */
class DerGoldenTest {

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun bytes(h: String) =
        ByteArray(h.length / 2) {
            ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte()
        }

    // KeyDescription + attestation extension used across the reader tests (BouncyCastle 1.85).
    private val keyDescriptionHex =
        "30818b020201900a0101020201900a010104096368616c6c656e676504003014bf853d0802060191" +
            "1ee1cc00bf8554040402abcd3058a1083106020102020103a203020103a30402020100bf8377020500" +
            "bf853e03020100bf85401330110404010203040101ff0a01000403090909bf85410502030222e0bf85" +
            "420602040134d9a5bf8553080406333536373839"

    private val attExtensionHex =
        "30819d060a2b06010401d67902011104818e30818b020201900a0101020201900a01010409636861" +
            "6c6c656e676504003014bf853d08020601911ee1cc00bf8554040402abcd3058a1083106020102020103" +
            "a203020103a30402020100bf8377020500bf853e03020100bf85401330110404010203040101ff0a0100" +
            "0403090909bf85410502030222e0bf85420602040134d9a5bf8553080406333536373839"

    @Test
    fun primitives() {
        assertEquals("020100", hex(Der.integer(0)))
        assertEquals("02017f", hex(Der.integer(127)))
        assertEquals("02020080", hex(Der.integer(128)))
        assertEquals("02020100", hex(Der.integer(256)))
        assertEquals("020300ffff", hex(Der.integer(65535)))
        assertEquals("020601911ee1cc00", hex(Der.integer(1722800000000L)))
        assertEquals(
            "021100b3a1c2d4e5f60718293a4b5c6d7e8f90",
            hex(Der.integer(BigInteger("00b3a1c2d4e5f60718293a4b5c6d7e8f90", 16))),
        )
        assertEquals("0a0101", hex(Der.enumerated(1)))
        assertEquals("0101ff", hex(Der.bool(true)))
        assertEquals("0500", hex(Der.nullValue()))
        assertEquals("0403010203", hex(Der.octetString(byteArrayOf(1, 2, 3))))
        assertEquals("0400", hex(Der.octetString(ByteArray(0))))
        assertEquals("060a2b06010401d679020111", hex(Der.oid("1.3.6.1.4.1.11129.2.1.17")))
        assertEquals("06082a8648ce3d040302", hex(Der.oid("1.2.840.10045.4.3.2")))
    }

    @Test
    fun highTagNumbersAndSetSorting() {
        assertEquals("bf85400302012a", hex(Der.explicit(704, Der.integer(42))))
        assertEquals("bf8553050403090807", hex(Der.explicit(723, Der.octetString(byteArrayOf(9, 8, 7)))))
        // DER SET OF must sort by encoding regardless of input order.
        assertEquals(
            "310a02010102010202020100",
            hex(Der.set(listOf(Der.integer(256), Der.integer(1), Der.integer(2)))),
        )
    }

    @Test
    fun keyDescriptionMatchesGolden() {
        val tee =
            Der.sequence(
                Der.explicit(1, Der.set(listOf(Der.integer(2), Der.integer(3)))),
                Der.explicit(2, Der.integer(3)),
                Der.explicit(3, Der.integer(256)),
                Der.explicit(503, Der.nullValue()),
                Der.explicit(702, Der.integer(0)),
                Der.explicit(
                    704,
                    Der.sequence(
                        Der.octetString(byteArrayOf(1, 2, 3, 4)),
                        Der.bool(true),
                        Der.enumerated(0),
                        Der.octetString(byteArrayOf(9, 9, 9)),
                    ),
                ),
                Der.explicit(705, Der.integer(140000)),
                Der.explicit(706, Der.integer(20240805)),
                Der.explicit(723, Der.octetString("356789".toByteArray())),
            )
        val softwareEnforced =
            Der.sequence(
                Der.explicit(701, Der.integer(1722800000000L)),
                Der.explicit(724, Der.octetString(byteArrayOf(0xab.toByte(), 0xcd.toByte()))),
            )
        val keyDescription =
            Der.sequence(
                Der.integer(400),
                Der.enumerated(1),
                Der.integer(400),
                Der.enumerated(1),
                Der.octetString("challenge".toByteArray()),
                Der.octetString(ByteArray(0)),
                softwareEnforced,
                tee,
            )
        assertEquals(keyDescriptionHex, hex(keyDescription))
        assertEquals(
            attExtensionHex,
            hex(Der.sequence(Der.oid("1.3.6.1.4.1.11129.2.1.17"), Der.octetString(keyDescription))),
        )
    }

    @Test
    fun readerParsesAndRoundTripsKeyDescription() {
        val keyDescription = bytes(keyDescriptionHex)
        val fields = DerReader.children(DerReader.readOne(keyDescription).value)
        assertEquals(8, fields.size)
        assertEquals(400, fields[0].positiveInt().toInt())

        // Reconstructing from the parsed children must reproduce the original bytes exactly.
        assertArrayEquals(keyDescription, Der.sequence(fields.map { it.encoded }))

        val teeByTag = DerReader.children(fields[7].value).associateBy { it.tagNo }
        assertTrue(teeByTag.containsKey(AttestationTags.ROOT_OF_TRUST))
        val rootOfTrust = DerReader.children(teeByTag.getValue(AttestationTags.ROOT_OF_TRUST).inner().value)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), rootOfTrust[0].value) // verified boot key
        assertArrayEquals(byteArrayOf(9, 9, 9), rootOfTrust[3].value) // verified boot hash
        assertEquals(140000, teeByTag.getValue(AttestationTags.OS_VERSION).inner().positiveInt().toInt())

        val softwareByTag = DerReader.children(fields[6].value).associateBy { it.tagNo }
        assertArrayEquals(
            byteArrayOf(0xab.toByte(), 0xcd.toByte()),
            softwareByTag.getValue(AttestationTags.MODULE_HASH).inner().value,
        )
    }

    @Test
    fun extensionDoubleStripMatchesPatcherIdiom() {
        // X509Certificate.getExtensionValue(...) returns the extnValue OCTET STRING that wraps the
        // KeyDescription SEQUENCE; the patcher strips both layers before reading the fields.
        val extnValue = Der.octetString(bytes(keyDescriptionHex))
        val fields = DerReader.children(DerReader.readOne(extnValue).inner().value)
        assertEquals(8, fields.size)
    }

    private object AttestationTags {
        const val ROOT_OF_TRUST = 704
        const val OS_VERSION = 705
        const val MODULE_HASH = 724
    }
}
