package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils

/**
 * A utility object for handling cryptographic certificates and keys. Provides functions for
 * parsing, serialization, and conversion between different formats.
 */
object CertificateHelper {

    // Lazy-initialized CertificateFactory for X.509 certificates.
    private val certificateFactory: CertificateFactory by lazy {
        CertificateFactory.getInstance("X.509")
    }

    /**
     * Represents the result of an operation that can either succeed with data or fail with an
     * error.
     *
     * @param T The type of the successful data.
     */
    sealed class OperationResult<out T> {
        data class Success<T>(val data: T) : OperationResult<T>()

        data class Error(val message: String, val cause: Throwable? = null) :
            OperationResult<Nothing>()
    }

    /**
     * Parses a single X.509 certificate from a byte array.
     *
     * @param bytes The raw byte representation of the certificate.
     * @return An [OperationResult.Success] containing the [X509Certificate], or an
     *   [OperationResult.Error] on failure.
     */
    fun toCertificate(bytes: ByteArray): OperationResult<X509Certificate> {
        return try {
            val certificate =
                certificateFactory.generateCertificate(ByteArrayInputStream(bytes))
                    as X509Certificate
            OperationResult.Success(certificate)
        } catch (e: CertificateException) {
            SystemLogger.warning("Failed to parse X.509 certificate from byte array.", e)
            OperationResult.Error("Failed to parse certificate", e)
        }
    }

    /**
     * Parses a collection of X.509 certificates from a byte array.
     *
     * @param bytes The raw byte representation of one or more concatenated certificates.
     * @return A collection of [X509Certificate] objects. Returns an empty list on failure.
     */
    @Suppress("UNCHECKED_CAST")
    fun toCertificates(bytes: ByteArray?): Collection<X509Certificate> {
        return bytes?.let {
            try {
                certificateFactory.generateCertificates(ByteArrayInputStream(it))
                    as Collection<X509Certificate>
            } catch (e: CertificateException) {
                SystemLogger.warning("Could not parse certificate collection from byte array.", e)
                emptyList()
            }
        } ?: emptyList()
    }

    /**
     * Serializes a collection of certificates into a single byte array by concatenating their
     * encoded forms.
     *
     * @param certificates The collection of [Certificate] objects to serialize.
     * @return A [ByteArray] containing the concatenated certificates, or `null` on failure.
     */
    fun certificatesToByteArray(certificates: Collection<Certificate>): ByteArray? {
        return runCatching {
            ByteArrayOutputStream().use { stream ->
                certificates.forEach { cert -> stream.write(cert.encoded) }
                stream.toByteArray()
            }
        }
            .onFailure {
                SystemLogger.warning(
                    "Failed to serialize certificate collection to byte array.",
                    it,
                )
            }
            .getOrNull()
    }

    /**
     * Parses a PEM-encoded private key and converts it into a Java [KeyPair].
     *
     * @param pemContent The string containing the PEM-encoded key.
     * @return An [OperationResult.Success] with the [KeyPair], or an [OperationResult.Error] on
     *   failure.
     */
    fun parsePemKeyPair(
        pemContent: String,
        publicKey: PublicKey,
    ): OperationResult<KeyPair> {
        return try {
            val pem = readPemBlock(pemContent)
            val pkcs8 =
                when (pem.type) {
                    "PRIVATE KEY" -> pem.content
                    "EC PRIVATE KEY" ->
                        wrapPkcs8(
                            pem.content,
                            OID_EC_PUBLIC_KEY,
                            extractEcParameters(pem.content, publicKey),
                        )
                    "RSA PRIVATE KEY" -> wrapPkcs8(pem.content, OID_RSA_ENCRYPTION, derNull())
                    else -> throw IllegalArgumentException("Unsupported PEM key type: ${pem.type}")
                }
            OperationResult.Success(KeyPair(publicKey, generatePrivateKey(pkcs8, publicKey)))
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse PEM key pair.", e)
            OperationResult.Error("Failed to parse PEM key pair", e)
        }
    }

    /**
     * Parses a PEM-encoded X.509 certificate.
     *
     * @param pemContent The string containing the PEM-encoded certificate.
     * @return An [OperationResult.Success] with the [Certificate], or an [OperationResult.Error] on
     *   failure.
     */
    fun parsePemCertificate(pemContent: String): OperationResult<Certificate> {
        return try {
            val pem = readPemBlock(pemContent)
            require(pem.type == "CERTIFICATE") { "Unsupported PEM certificate type: ${pem.type}" }
            val certificate =
                certificateFactory.generateCertificate(ByteArrayInputStream(pem.content))
            OperationResult.Success(certificate)
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse PEM certificate.", e)
            OperationResult.Error("Failed to parse PEM certificate", e)
        }
    }

    /** DER `AlgorithmIdentifier` for a certificate signature algorithm. */
    fun signatureAlgorithmIdentifier(algorithm: String): ByteArray =
        when (normalizeSignatureAlgorithm(algorithm)) {
            "SHA256withECDSA" -> Der.sequence(Der.oid(OID_SHA256_WITH_ECDSA))
            "SHA256withRSA" ->
                Der.sequence(Der.oid(OID_SHA256_WITH_RSA_ENCRYPTION), Der.nullValue())
            else -> throw IllegalArgumentException("Unsupported signature algorithm: $algorithm")
        }

    /** Signs [data] with [privateKey] using the (normalized) JCA signature [algorithm]. */
    fun sign(algorithm: String, privateKey: PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance(normalizeSignatureAlgorithm(algorithm))
            .apply {
                initSign(privateKey)
                update(data)
            }
            .sign()

    /** Parses a DER-encoded certificate, throwing on failure. */
    fun decodeCertificate(der: ByteArray): X509Certificate =
        certificateFactory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private const val OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
    private const val OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
    private const val OID_SHA256_WITH_ECDSA = "1.2.840.10045.4.3.2"
    private const val OID_SHA256_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.11"

    private data class PemBlock(val type: String, val content: ByteArray)

    private data class DerTlv(val tag: Int, val value: ByteArray, val encoded: ByteArray)

    private class DerReader(private val bytes: ByteArray) {
        private var offset = 0

        fun hasRemaining(): Boolean = offset < bytes.size

        fun readTlv(): DerTlv {
            val start = offset
            val tag = readByte()
            val length = readLength()
            require(offset + length <= bytes.size) { "DER length exceeds input size" }
            val valueStart = offset
            offset += length
            return DerTlv(
                tag,
                bytes.copyOfRange(valueStart, offset),
                bytes.copyOfRange(start, offset),
            )
        }

        private fun readByte(): Int {
            require(offset < bytes.size) { "Unexpected end of DER input" }
            return bytes[offset++].toInt() and 0xff
        }

        private fun readLength(): Int {
            val first = readByte()
            if ((first and 0x80) == 0) return first
            val count = first and 0x7f
            require(count in 1..4) { "Unsupported DER length form" }
            var length = 0
            repeat(count) { length = (length shl 8) or readByte() }
            return length
        }
    }

    private fun readPemBlock(pemContent: String): PemBlock {
        val lines = pemContent.trim().lines().map { it.trim() }.filter { it.isNotEmpty() }
        val beginIndex = lines.indexOfFirst { it.startsWith("-----BEGIN ") && it.endsWith("-----") }
        require(beginIndex >= 0) { "PEM begin marker not found" }
        val type = lines[beginIndex].removePrefix("-----BEGIN ").removeSuffix("-----")
        val endMarker = "-----END $type-----"
        val endIndex = lines.indexOfFirst { it == endMarker }
        require(endIndex > beginIndex) { "PEM end marker not found for $type" }
        val body = lines.subList(beginIndex + 1, endIndex).joinToString("")
        return PemBlock(type, Base64.getMimeDecoder().decode(body))
    }

    private fun generatePrivateKey(pkcs8: ByteArray, publicKey: PublicKey): PrivateKey {
        val algorithms =
            listOf(publicKey.algorithm, "EC", "RSA")
                .map { if (it.equals("ECDSA", ignoreCase = true)) "EC" else it }
                .distinct()
        var lastError: Exception? = null
        for (algorithm in algorithms) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            } catch (e: Exception) {
                lastError = e
            }
        }
        throw IllegalArgumentException("Unsupported private key algorithm", lastError)
    }

    private fun normalizeSignatureAlgorithm(algorithm: String): String =
        when (algorithm.uppercase().replace("-", "")) {
            "SHA256WITHECDSA" -> "SHA256withECDSA"
            "SHA256WITHRSA" -> "SHA256withRSA"
            else -> algorithm
        }

    private fun extractEcParameters(
        sec1PrivateKey: ByteArray,
        publicKey: PublicKey,
    ): ByteArray {
        val sequence = DerReader(sec1PrivateKey).readTlv()
        require(sequence.tag == 0x30) { "EC private key is not a DER sequence" }
        val reader = DerReader(sequence.value)
        while (reader.hasRemaining()) {
            val field = reader.readTlv()
            if (field.tag == 0xa0) {
                val params = DerReader(field.value).readTlv()
                require(params.tag == 0x06) { "EC parameters are not a named-curve OID" }
                return params.encoded
            }
        }
        val fieldSize = (publicKey as? ECPublicKey)?.params?.curve?.field?.fieldSize
        val inferredOid =
            when (fieldSize) {
                256 -> "1.2.840.10045.3.1.7"
                384 -> "1.3.132.0.34"
                521 -> "1.3.132.0.35"
                else -> null
            }
        return inferredOid?.let { derOid(it) }
            ?: throw IllegalArgumentException("EC private key does not contain named-curve parameters")
    }

    private fun wrapPkcs8(
        privateKey: ByteArray,
        algorithmOid: String,
        parameters: ByteArray,
    ): ByteArray =
        derSequence(
            derIntegerZero(),
            derSequence(derOid(algorithmOid), parameters),
            derOctetString(privateKey),
        )

    private fun derIntegerZero(): ByteArray = byteArrayOf(0x02, 0x01, 0x00)

    private fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)

    private fun derOctetString(value: ByteArray): ByteArray = der(0x04, value)

    private fun derSequence(vararg elements: ByteArray): ByteArray =
        der(0x30, elements.fold(ByteArray(0)) { acc, element -> acc + element })

    private fun derOid(oid: String): ByteArray {
        val arcs = oid.split('.').map { it.toLong() }
        require(arcs.size >= 2 && arcs[0] in 0..2 && arcs[1] in 0..39) { "Invalid OID: $oid" }
        val body = ByteArrayOutputStream()
        body.write((arcs[0] * 40 + arcs[1]).toInt())
        arcs.drop(2).forEach { arc -> writeOidArc(body, arc) }
        return der(0x06, body.toByteArray())
    }

    private fun writeOidArc(
        stream: ByteArrayOutputStream,
        arc: Long,
    ) {
        require(arc >= 0) { "Negative OID arc" }
        val bytes = mutableListOf((arc and 0x7f).toInt())
        var value = arc ushr 7
        while (value > 0) {
            bytes.add(0, ((value and 0x7f).toInt() or 0x80))
            value = value ushr 7
        }
        bytes.forEach { stream.write(it) }
    }

    private fun der(
        tag: Int,
        value: ByteArray,
    ): ByteArray = byteArrayOf(tag.toByte()) + derLength(value.size) + value

    private fun derLength(length: Int): ByteArray {
        require(length >= 0) { "Negative DER length" }
        if (length < 0x80) return byteArrayOf(length.toByte())
        var value = length
        val bytes = mutableListOf<Byte>()
        while (value > 0) {
            bytes.add(0, (value and 0xff).toByte())
            value = value ushr 8
        }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    /**
     * Extracts the full certificate chain from a KeyStore [KeyMetadata] object.
     *
     * @param metadata The metadata associated with a keystore key entry.
     * @return An array of [Certificate] objects, with the leaf certificate at index 0, or `null`.
     */
    fun getCertificateChain(metadata: KeyMetadata?): Array<Certificate>? {
        metadata ?: return null
        val leafCertBytes = metadata.certificate ?: return null
        val leafCert =
            (toCertificate(leafCertBytes) as? OperationResult.Success)?.data ?: return null

        val chainBytes = metadata.certificateChain
        return if (chainBytes == null) {
            arrayOf(leafCert)
        } else {
            val additionalCerts = toCertificates(chainBytes)
            (listOf(leafCert) + additionalCerts).toTypedArray()
        }
    }

    /**
     * Extracts the full certificate chain from a [KeyEntryResponse].
     *
     * @param response The response object from a keystore operation.
     * @return An array of [Certificate] objects, or `null`.
     */
    fun getCertificateChain(response: KeyEntryResponse?): Array<Certificate>? {
        return response?.let { getCertificateChain(it.metadata) }
    }

    /**
     * Updates the certificate chain and patches authorizations within a [KeyMetadata] object.
     *
     * @param callingUid The UID of the application to fetch specific patch levels for.
     * @param metadata The metadata object to modify.
     * @param chain The new certificate chain to set. The leaf must be at index 0.
     * @return A [Result] indicating success or failure.
     */
    fun updateCertificateChain(
        callingUid: Int,
        metadata: KeyMetadata,
        chain: Array<Certificate>,
    ): Result<Unit> {
        return runCatching {
            require(chain.isNotEmpty()) { "Certificate chain cannot be empty." }

            // Update the certificate fields
            metadata.certificate = chain[0].encoded
            metadata.certificateChain =
                if (chain.size > 1) {
                    certificatesToByteArray(chain.drop(1))
                } else {
                    null
                }

            // Patch authorizations to match user configurations
            metadata.authorizations =
                metadata.authorizations
                    ?.mapNotNull { auth ->
                        val replacement =
                            when (auth.keyParameter.tag) {
                                Tag.OS_PATCHLEVEL -> AndroidDeviceUtils.getPatchLevel(callingUid)
                                Tag.VENDOR_PATCHLEVEL ->
                                    AndroidDeviceUtils.getVendorPatchLevelLong(callingUid)
                                Tag.BOOT_PATCHLEVEL ->
                                    AndroidDeviceUtils.getBootPatchLevelLong(callingUid)
                                else -> return@mapNotNull auth // Keep all other tags
                            }

                        // If configured to hide, return null to filter out of the array
                        if (replacement == AndroidDeviceUtils.DO_NOT_REPORT) {
                            null
                        } else {
                            // Create patched authorization preserving original security level
                            Authorization().apply {
                                securityLevel = auth.securityLevel
                                keyParameter =
                                    KeyParameter().apply {
                                        tag = auth.keyParameter.tag
                                        value = KeyParameterValue.integer(replacement)
                                    }
                            }
                        }
                    }
                    ?.toTypedArray()
        }
    }
}
