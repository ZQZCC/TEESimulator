package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyPurpose
import android.os.Build
import android.util.Pair
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.TimeZone
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Responsible for generating new cryptographic key pairs and X.509 certificate chains.
 *
 * This object simulates the behavior of the Android KeyMint/Keymaster HAL by creating certificates
 * that include a fully-featured, simulated attestation extension.
 */
object CertificateGenerator {

    // AOSP utils.rs: pub const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;
    // RFC 5280 GeneralizedTime maximum: 9999-12-31T23:59:59 UTC (millis since epoch)
    private const val UNDEFINED_NOT_AFTER = 253402300799000L

    /**
     * Generates a software-based cryptographic key pair.
     *
     * @param params The parameters specifying the key's algorithm, size, and other properties.
     * @return A new [KeyPair], or `null` on failure.
     */
    fun generateSoftwareKeyPair(params: KeyMintAttestation): KeyPair? {
        return runCatching {
                val (algorithm, spec) =
                    when (params.algorithm) {
                        Algorithm.EC -> "EC" to ECGenParameterSpec(params.ecCurveName)
                        Algorithm.RSA ->
                            "RSA" to
                                RSAKeyGenParameterSpec(
                                    params.keySize,
                                    params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4,
                                )
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported algorithm: ${params.algorithm}"
                            )
                    }
                SystemLogger.debug("Generating $algorithm key pair with size ${params.keySize}")
                KeyPairGenerator.getInstance(algorithm).apply { initialize(spec) }.generateKeyPair()
            }
            .onFailure { SystemLogger.error("Failed to generate software key pair.", it) }
            .getOrNull()
    }

    /**
     * Generates a certificate chain for a given key pair. This is the primary function for creating
     * attested certificates.
     *
     * @param uid The UID of the application requesting the key.
     * @param subjectKeyPair The key pair for which the certificate will be generated.
     * @param attestKeyAlias Optional alias of a key to use for attestation signing.
     * @param params The parameters for the new key and its attestation.
     * @param securityLevel The security level to embed in the attestation.
     * @return A [List] of [Certificate] forming the new chain, or `null` on failure.
     */
    fun generateCertificateChain(
        uid: Int,
        subjectKeyPair: KeyPair,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): List<Certificate>? {
        val challenge = params.attestationChallenge
        if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT)
            throw IllegalArgumentException(
                "Attestation challenge exceeds length limit (${challenge.size} > ${AttestationConstants.CHALLENGE_LENGTH_LIMIT})"
            )

        return runCatching {
                val keybox = getKeyboxForAlgorithm(uid, params.algorithm)

                // Determine the signing key and issuer. If an attestKey is provided, use it.
                // Otherwise, fall back to the root key from the keybox.
                val (signingKey, issuer) =
                    if (attestKeyAlias != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        getAttestationKeyInfo(uid, attestKeyAlias)?.let { it.first to it.second }
                            ?: (keybox.keyPair to getIssuerFromKeybox(keybox))
                    } else {
                        keybox.keyPair to getIssuerFromKeybox(keybox)
                    }

                // Build the new leaf certificate with the simulated attestation.
                val leafCert =
                    buildCertificate(subjectKeyPair, signingKey, issuer, params, uid, securityLevel)

                // If not self-attesting, the chain is just the leaf. Otherwise, append the keybox
                // chain.
                if (attestKeyAlias != null) {
                    listOf(leafCert)
                } else {
                    listOf(leafCert) + keybox.certificates
                }
            }
            .onFailure { SystemLogger.error("Failed to generate certificate chain.", it) }
            .getOrNull()
    }

    /**
     * A convenience function that combines key pair generation and certificate chain generation.
     * Primarily used by the modern Keystore2 interceptor where generation is a single step.
     */
    fun generateAttestedKeyPair(
        uid: Int,
        alias: String,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): Pair<KeyPair, List<Certificate>>? {
        return runCatching {
                SystemLogger.info(
                    "Generating new attested key pair for alias: '$alias' (UID: $uid)"
                )
                val newKeyPair =
                    generateSoftwareKeyPair(params)
                        ?: throw Exception("Failed to generate underlying software key pair.")

                val chain =
                    generateCertificateChain(uid, newKeyPair, attestKeyAlias, params, securityLevel)
                        ?: throw Exception("Failed to generate certificate chain for new key pair.")

                SystemLogger.info(
                    "Successfully generated new certificate chain for alias: '$alias'."
                )
                Pair(newKeyPair, chain)
            }
            .onFailure {
                SystemLogger.error("Failed to generate attested key pair for alias '$alias'.", it)
            }
            .getOrNull()
    }

    fun getIssuerFromKeybox(keybox: KeyBox): ByteArray =
        (keybox.certificates[0] as X509Certificate).subjectX500Principal.encoded

    private fun getKeyboxForAlgorithm(uid: Int, algorithm: Int): KeyBox {
        val keyboxFile = ConfigurationManager.getKeyboxFileForUid(uid)
        val algorithmName =
            when (algorithm) {
                Algorithm.EC -> "EC"
                Algorithm.RSA -> "RSA"
                else -> throw IllegalArgumentException("Unsupported algorithm ID: $algorithm")
            }
        return KeyBoxManager.getAttestationKey(keyboxFile, algorithmName)
            ?: throw Exception("Could not load keybox for UID $uid and algorithm $algorithmName")
    }

    /** Retrieves the key pair and DER-encoded issuer name for a given attestation key alias. */
    private fun getAttestationKeyInfo(uid: Int, attestKeyAlias: String): Pair<KeyPair, ByteArray>? {
        SystemLogger.debug("Looking for attestation key: uid=$uid alias=$attestKeyAlias")
        val keyId = KeyIdentifier(uid, attestKeyAlias)
        // Access the public map of generated keys
        val keyInfo = KeyMintSecurityLevelInterceptor.generatedKeys[keyId]
        return if (keyInfo != null) {
            val certChain = CertificateHelper.getCertificateChain(keyInfo.response)
            if (!certChain.isNullOrEmpty()) {
                val issuer = (certChain[0] as X509Certificate).subjectX500Principal.encoded
                Pair(keyInfo.keyPair, issuer)
            } else {
                null
            }
        } else {
            SystemLogger.warning(
                "Attestation key '$attestKeyAlias' not found in generated key cache."
            )
            null
        }
    }

    // X.509 KeyUsage named-bit values (matching the historical BouncyCastle constants).
    private const val KU_DIGITAL_SIGNATURE = 1 shl 7
    private const val KU_DATA_ENCIPHERMENT = 1 shl 4
    private const val KU_KEY_ENCIPHERMENT = 1 shl 5
    private const val KU_KEY_AGREEMENT = 1 shl 3
    private const val KU_KEY_CERT_SIGN = 1 shl 2

    private const val OID_KEY_USAGE = "2.5.29.15"

    /** Maps KeyPurpose values to X.509 KeyUsage bits per KeyCreationResult.aidl spec */
    private fun buildKeyUsageFromPurposes(purposes: List<Int>): Int {
        var bits = 0
        for (purpose in purposes) {
            bits =
                bits or
                    when (purpose) {
                        KeyPurpose.SIGN -> KU_DIGITAL_SIGNATURE
                        KeyPurpose.DECRYPT -> KU_DATA_ENCIPHERMENT
                        KeyPurpose.WRAP_KEY -> KU_KEY_ENCIPHERMENT
                        KeyPurpose.AGREE_KEY -> KU_KEY_AGREEMENT
                        KeyPurpose.ATTEST_KEY -> KU_KEY_CERT_SIGN
                        else -> 0
                    }
        }
        return bits
    }

    /** DER BIT STRING encoding of an X.509 KeyUsage value (named bits, trailing zeros trimmed). */
    private fun encodeKeyUsage(usage: Int): ByteArray {
        val two = byteArrayOf((usage and 0xff).toByte(), ((usage shr 8) and 0xff).toByte())
        var length = two.size
        while (length > 1 && two[length - 1].toInt() == 0) length--
        val last = two[length - 1].toInt() and 0xff
        var unused = 0
        if (last == 0) {
            unused = 8
        } else {
            var mask = 1
            while ((last and mask) == 0) {
                mask = mask shl 1
                unused++
            }
        }
        val content = ByteArray(1 + length)
        content[0] = unused.toByte()
        System.arraycopy(two, 0, content, 1, length)
        return Der.tlv(0x03, content)
    }

    /** X.509 validity time: UTCTime for years 1950-2049, GeneralizedTime otherwise. */
    private fun encodeTime(date: Date): ByteArray {
        val calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        calendar.time = date
        val year = calendar.get(Calendar.YEAR)
        return if (year in 1950..2049) {
            val formatter =
                SimpleDateFormat("yyMMddHHmmss'Z'").apply { timeZone = TimeZone.getTimeZone("UTC") }
            Der.tlv(0x17, formatter.format(date).toByteArray(Charsets.US_ASCII))
        } else {
            val formatter =
                SimpleDateFormat("yyyyMMddHHmmss'Z'").apply {
                    timeZone = TimeZone.getTimeZone("UTC")
                }
            Der.tlv(0x18, formatter.format(date).toByteArray(Charsets.US_ASCII))
        }
    }

    // DER of the default subject Name: CN=Android Keystore Key (verified against BouncyCastle).
    private val DEFAULT_SUBJECT_DER =
        byteArrayOf(
            0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41,
            0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x4b, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72,
            0x65, 0x20, 0x4b, 0x65, 0x79,
        )

    /** Constructs a new X.509 certificate with a simulated attestation extension. */
    private fun buildCertificate(
        subjectKeyPair: KeyPair,
        signingKeyPair: KeyPair,
        issuer: ByteArray,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Certificate {
        val subject = params.certificateSubject ?: DEFAULT_SUBJECT_DER

        // AOSP add_required_parameters (security_level.rs) defaults:
        //   CERTIFICATE_NOT_BEFORE = 0 (Unix epoch)
        //   CERTIFICATE_NOT_AFTER  = 253402300799000 (9999-12-31T23:59:59 UTC)
        val notBefore = params.certificateNotBefore ?: Date(0)
        val notAfter = params.certificateNotAfter ?: Date(UNDEFINED_NOT_AFTER)
        val serial = params.certificateSerial ?: BigInteger.ONE

        val signerAlgorithm =
            when (signingKeyPair.private) {
                is ECKey -> "SHA256withECDSA"
                is RSAKey -> "SHA256withRSA"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported signing key type: ${signingKeyPair.private.javaClass}"
                    )
            }
        val algorithmIdentifier = CertificateHelper.signatureAlgorithmIdentifier(signerAlgorithm)

        val extensions = mutableListOf<ByteArray>()
        val keyUsageBits = buildKeyUsageFromPurposes(params.purpose)
        if (keyUsageBits != 0) {
            extensions.add(
                Der.sequence(
                    Der.oid(OID_KEY_USAGE),
                    Der.bool(true), // critical
                    Der.octetString(encodeKeyUsage(keyUsageBits)),
                )
            )
        }
        extensions.add(AttestationBuilder.buildAttestationExtension(params, uid, securityLevel))

        // TBSCertificate: subject/issuer names and the SubjectPublicKeyInfo are already DER.
        val tbsCertificate =
            Der.sequence(
                Der.explicit(0, Der.integer(2)), // version v3
                Der.integer(serial),
                algorithmIdentifier,
                issuer,
                Der.sequence(encodeTime(notBefore), encodeTime(notAfter)),
                subject,
                subjectKeyPair.public.encoded,
                Der.explicit(3, Der.sequence(extensions)),
            )

        val signature =
            CertificateHelper.sign(signerAlgorithm, signingKeyPair.private, tbsCertificate)
        val certificate =
            Der.sequence(tbsCertificate, algorithmIdentifier, Der.bitStringNoUnused(signature))
        return CertificateHelper.decodeCertificate(certificate)
    }
}
