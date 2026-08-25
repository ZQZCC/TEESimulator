package org.matrix.TEESimulator.attestation

import android.content.pm.PackageManager
import android.os.Build
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.pki.Der
import org.matrix.TEESimulator.util.AndroidDeviceUtils
import org.matrix.TEESimulator.util.AndroidDeviceUtils.DO_NOT_REPORT

/**
 * A builder object responsible for constructing the ASN.1 DER-encoded Android Key Attestation
 * extension. All output is raw DER produced via [Der].
 */
object AttestationBuilder {

    /**
     * Builds the complete X.509 attestation extension as DER bytes: a `SEQUENCE { OID, OCTET STRING }`
     * where the octet string wraps the encoded `KeyDescription`.
     */
    fun buildAttestationExtension(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): ByteArray {
        val keyDescription = buildKeyDescription(params, uid, securityLevel)
        return Der.sequence(Der.oid(ATTESTATION_OID), Der.octetString(keyDescription))
    }

    /** DER-encoded `RootOfTrust` SEQUENCE. */
    internal fun rootOfTrustBytes(): ByteArray {
        val elements = arrayOfNulls<ByteArray>(4)
        elements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX] =
            Der.octetString(AndroidDeviceUtils.bootKey)
        elements[AttestationConstants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX] = Der.bool(true)
        elements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX] = Der.enumerated(0)
        elements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX] =
            Der.octetString(AndroidDeviceUtils.bootHash)
        return Der.sequence(elements.map { it!! })
    }

    /**
     * Simulated hardware properties as DER `[tag] EXPLICIT` fragments, keyed by attestation tag. A
     * null value means the property should be removed.
     */
    internal fun simulatedHardwarePropertyBytes(uid: Int): Map<Int, ByteArray?> {
        val properties = LinkedHashMap<Int, ByteArray?>()

        properties[AttestationConstants.TAG_OS_VERSION] =
            Der.explicit(
                AttestationConstants.TAG_OS_VERSION,
                Der.integer(AndroidDeviceUtils.osVersion.toLong()),
            )

        val osPatch = AndroidDeviceUtils.getPatchLevel(uid)
        properties[AttestationConstants.TAG_OS_PATCHLEVEL] =
            if (osPatch != DO_NOT_REPORT)
                Der.explicit(AttestationConstants.TAG_OS_PATCHLEVEL, Der.integer(osPatch.toLong()))
            else null

        val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(uid)
        properties[AttestationConstants.TAG_VENDOR_PATCHLEVEL] =
            if (vendorPatch != DO_NOT_REPORT)
                Der.explicit(
                    AttestationConstants.TAG_VENDOR_PATCHLEVEL,
                    Der.integer(vendorPatch.toLong()),
                )
            else null

        val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(uid)
        properties[AttestationConstants.TAG_BOOT_PATCHLEVEL] =
            if (bootPatch != DO_NOT_REPORT)
                Der.explicit(AttestationConstants.TAG_BOOT_PATCHLEVEL, Der.integer(bootPatch.toLong()))
            else null

        return properties
    }

    /** Constructs the main `KeyDescription` SEQUENCE, which is the core of the attestation. */
    private fun buildKeyDescription(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): ByteArray {
        val teeEnforced = buildTeeEnforcedList(params, uid, securityLevel)
        val softwareEnforced = buildSoftwareEnforcedList(params, uid, securityLevel)

        return Der.sequence(
            Der.integer(AndroidDeviceUtils.getAttestVersion(securityLevel).toLong()),
            Der.enumerated(securityLevel.toLong()),
            Der.integer(AndroidDeviceUtils.getKeymasterVersion(securityLevel).toLong()),
            Der.enumerated(securityLevel.toLong()),
            Der.octetString(params.attestationChallenge ?: ByteArray(0)),
            Der.octetString(ByteArray(0)), // uniqueId
            softwareEnforced,
            teeEnforced,
        )
    }

    /** Builds the `TeeEnforced` authorization list, sorted by tag as AOSP expects. */
    private fun buildTeeEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): ByteArray {
        val list = mutableListOf<Pair<Int, ByteArray>>()

        fun add(tag: Int, value: ByteArray) = list.add(tag to Der.explicit(tag, value))

        add(
            AttestationConstants.TAG_PURPOSE,
            Der.set(params.purpose.map { Der.integer(it.toLong()) }),
        )
        add(AttestationConstants.TAG_ALGORITHM, Der.integer(params.algorithm.toLong()))
        add(AttestationConstants.TAG_KEY_SIZE, Der.integer(params.keySize.toLong()))
        add(
            AttestationConstants.TAG_DIGEST,
            Der.set(params.digest.map { Der.integer(it.toLong()) }),
        )

        if (params.ecCurve != null) {
            add(AttestationConstants.TAG_EC_CURVE, Der.integer(params.ecCurve.toLong()))
        }
        if (params.padding.isNotEmpty()) {
            add(
                AttestationConstants.TAG_PADDING,
                Der.set(params.padding.map { Der.integer(it.toLong()) }),
            )
        }
        if (params.rsaPublicExponent != null) {
            add(
                AttestationConstants.TAG_RSA_PUBLIC_EXPONENT,
                Der.integer(params.rsaPublicExponent.toLong()),
            )
        }

        add(AttestationConstants.TAG_NO_AUTH_REQUIRED, Der.nullValue())
        add(AttestationConstants.TAG_ORIGIN, Der.integer(0L)) // KeyOrigin.GENERATED
        add(AttestationConstants.TAG_ROOT_OF_TRUST, rootOfTrustBytes())

        // Conditionally add simulated patch levels (already fully encoded [tag] EXPLICIT fragments).
        simulatedHardwarePropertyBytes(uid).forEach { (tag, bytes) ->
            if (bytes != null) list.add(tag to bytes)
        }

        params.brand?.let { add(AttestationConstants.TAG_ATTESTATION_ID_BRAND, Der.octetString(it)) }
        params.device?.let { add(AttestationConstants.TAG_ATTESTATION_ID_DEVICE, Der.octetString(it)) }
        params.product?.let { add(AttestationConstants.TAG_ATTESTATION_ID_PRODUCT, Der.octetString(it)) }
        params.serial?.let { add(AttestationConstants.TAG_ATTESTATION_ID_SERIAL, Der.octetString(it)) }
        params.imei?.let { add(AttestationConstants.TAG_ATTESTATION_ID_IMEI, Der.octetString(it)) }
        params.meid?.let { add(AttestationConstants.TAG_ATTESTATION_ID_MEID, Der.octetString(it)) }
        params.manufacturer?.let {
            add(AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER, Der.octetString(it))
        }
        params.model?.let { add(AttestationConstants.TAG_ATTESTATION_ID_MODEL, Der.octetString(it)) }
        if (AndroidDeviceUtils.getAttestVersion(securityLevel) >= 300) {
            params.secondImei?.let {
                add(AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI, Der.octetString(it))
            }
        }

        return Der.sequence(list.sortedBy { it.first }.map { it.second })
    }

    /** Builds the `SoftwareEnforced` authorization list (insertion order, as AOSP emits it). */
    private fun buildSoftwareEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): ByteArray {
        val list = mutableListOf<ByteArray>()

        list.add(
            Der.explicit(
                AttestationConstants.TAG_CREATION_DATETIME,
                Der.integer(System.currentTimeMillis()),
            )
        )

        // AOSP add_required_parameters only adds ATTESTATION_APPLICATION_ID when a challenge exists.
        if (params.attestationChallenge != null) {
            list.add(
                Der.explicit(
                    AttestationConstants.TAG_ATTESTATION_APPLICATION_ID,
                    createApplicationId(uid),
                )
            )
        }
        if (AndroidDeviceUtils.getAttestVersion(securityLevel) >= 400) {
            list.add(
                Der.explicit(
                    AttestationConstants.TAG_MODULE_HASH,
                    Der.octetString(AndroidDeviceUtils.moduleHash),
                )
            )
        }
        return Der.sequence(list)
    }

    /** Content-based equality wrapper so signature digests can be de-duplicated in a set. */
    private data class Digest(val digest: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            return digest.contentEquals((other as Digest).digest)
        }

        override fun hashCode(): Int = digest.contentHashCode()
    }

    /**
     * Creates the `AttestationApplicationId` structure as a DER OCTET STRING wrapping the id
     * SEQUENCE. It contains the package(s) and their signing certificate digests.
     */
    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): ByteArray {
        val pm =
            ConfigurationManager.getPackageManager()
                ?: throw IllegalStateException("PackageManager not found!")
        val packages =
            pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")

        val sha256 = MessageDigest.getInstance("SHA-256")
        val packageInfos = mutableListOf<ByteArray>()
        val signatureDigests = mutableSetOf<Digest>()

        packages.forEach { packageName ->
            val userId = uid / 100000
            val packageInfo =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                        userId,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES, userId)
                }

            packageInfos.add(
                Der.sequence(
                    Der.octetString(packageInfo.packageName.toByteArray(StandardCharsets.UTF_8)),
                    Der.integer(packageInfo.longVersionCode),
                )
            )

            packageInfo.signingInfo?.signingCertificateHistory?.forEach { signature ->
                signatureDigests.add(Digest(sha256.digest(signature.toByteArray())))
            }
        }

        val applicationIdSequence =
            Der.sequence(
                Der.set(packageInfos),
                Der.set(signatureDigests.map { Der.octetString(it.digest) }),
            )

        return Der.octetString(applicationIdSequence)
    }
}
