package org.matrix.TEESimulator.attestation

import android.security.keystore.KeyProperties
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper
import org.matrix.TEESimulator.pki.Der
import org.matrix.TEESimulator.pki.DerReader
import org.matrix.TEESimulator.pki.DerTlv
import org.matrix.TEESimulator.pki.KeyBox
import org.matrix.TEESimulator.pki.KeyBoxManager

/**
 * Handles the modification (patching) of Android Key Attestation extensions within certificates.
 *
 * It takes a certificate chain produced by the real TEE, replaces the attestation record's Root of
 * Trust and simulated device properties, re-issues the leaf under the configured keybox, and
 * re-signs it. All ASN.1 work is done on raw DER via [Der] / [DerReader].
 */
object AttestationPatcher {

    /**
     * Patches a full certificate chain by modifying the leaf's attestation and rebuilding the chain
     * with the keybox signing certificates. Returns the original chain on any failure.
     */
    fun patchCertificateChain(originalChain: Array<Certificate>?, uid: Int): Array<Certificate> {
        if (originalChain.isNullOrEmpty()) {
            SystemLogger.error("Attempted to patch a null or empty certificate chain for UID $uid.")
            return originalChain ?: emptyArray()
        }

        return runCatching {
                val originalLeaf = originalChain[0] as X509Certificate

                // No attestation extension means there is nothing to patch.
                val patchedKeyDescription =
                    patchAttestation(originalLeaf, uid) ?: return originalChain

                val keybox = getKeyboxForUidAndAlgorithm(uid, originalLeaf.sigAlgName)
                val patchedLeaf = rebuildLeaf(originalLeaf, patchedKeyDescription, keybox)

                val newChain = listOf(patchedLeaf) + keybox.certificates
                SystemLogger.info(
                    "Successfully rebuilt a valid, patched certificate chain for UID $uid."
                )
                newChain.toTypedArray()
            }
            .getOrElse {
                SystemLogger.error("Failed to patch and rebuild certificate chain for UID $uid.", it)
                originalChain
            }
    }

    /**
     * Reads the original attestation extension, replaces the RootOfTrust and simulated hardware
     * properties, and returns the new `KeyDescription` DER. Returns null when the leaf has no
     * attestation extension.
     */
    private fun patchAttestation(leaf: X509Certificate, uid: Int): ByteArray? {
        val extnValue = leaf.getExtensionValue(ATTESTATION_OID) ?: return null
        // getExtensionValue returns the extnValue OCTET STRING wrapping the KeyDescription SEQUENCE;
        // strip the octet string, then the sequence, to reach its fields.
        val fields = DerReader.children(DerReader.readOne(extnValue).inner().value)

        // A well-formed KeyDescription has softwareEnforced at index 6 and teeEnforced at 7. Some
        // certificates ship them swapped; detect that via where the RootOfTrust lives.
        val field6 = fields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX]
        val field7 = fields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX]
        val swapped = containsRootOfTrust(field6) && !containsRootOfTrust(field7)
        val softwareEnforced = if (swapped) field7 else field6
        val teeEnforced = if (swapped) field6 else field7

        // Rebuild the teeEnforced authorization list keyed by tag, preserving unrelated entries.
        val teeByTag = LinkedHashMap<Int, ByteArray>()
        DerReader.children(teeEnforced.value).forEach { tagged ->
            teeByTag[tagged.tagNo] = tagged.encoded
        }
        teeByTag[AttestationConstants.TAG_ROOT_OF_TRUST] =
            Der.explicit(
                AttestationConstants.TAG_ROOT_OF_TRUST,
                AttestationBuilder.rootOfTrustBytes(),
            )
        AttestationBuilder.simulatedHardwarePropertyBytes(uid).forEach { (tag, bytes) ->
            if (bytes != null) teeByTag[tag] = bytes else teeByTag.remove(tag)
        }
        val patchedTee = Der.sequence(teeByTag.entries.sortedBy { it.key }.map { it.value })

        return Der.sequence(
            fields[0].encoded,
            fields[1].encoded,
            fields[2].encoded,
            fields[3].encoded,
            fields[4].encoded,
            fields[5].encoded,
            softwareEnforced.encoded,
            patchedTee,
        )
    }

    private fun containsRootOfTrust(sequence: DerTlv): Boolean =
        DerReader.children(sequence.value).any {
            it.isContext && it.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST
        }

    /**
     * Rebuilds the leaf certificate: re-issues it under the keybox, swaps in the patched attestation
     * extension while preserving every other extension, and re-signs the TBSCertificate.
     */
    private fun rebuildLeaf(
        originalLeaf: X509Certificate,
        patchedKeyDescription: ByteArray,
        keybox: KeyBox,
    ): Certificate {
        val issuer = (keybox.certificates[0] as X509Certificate).subjectX500Principal.encoded
        val signerAlgorithm = originalLeaf.sigAlgName
        val algorithmIdentifier = CertificateHelper.signatureAlgorithmIdentifier(signerAlgorithm)
        val attestationOid = Der.oid(ATTESTATION_OID)
        val patchedExtension =
            Der.sequence(Der.oid(ATTESTATION_OID), Der.octetString(patchedKeyDescription))

        val tbs = DerReader.children(DerReader.readOne(originalLeaf.encoded).value)[0]
        val children = DerReader.children(tbs.value)
        val out = mutableListOf<ByteArray>()
        var i = 0
        if (children[0].isContext && children[0].tagNo == 0) {
            out.add(children[0].encoded) // version
            i = 1
        }
        out.add(children[i++].encoded) // serialNumber
        out.add(algorithmIdentifier) // signature algorithm (replaced)
        i++
        out.add(issuer) // issuer (replaced)
        i++
        out.add(children[i++].encoded) // validity
        out.add(children[i++].encoded) // subject
        out.add(children[i++].encoded) // subjectPublicKeyInfo
        while (i < children.size) {
            val child = children[i++]
            if (child.isContext && child.tagNo == 3) {
                val rebuilt =
                    DerReader.children(child.inner().value).map { ext ->
                        val oid = DerReader.children(ext.value)[0]
                        if (oid.encoded.contentEquals(attestationOid)) patchedExtension
                        else ext.encoded
                    }
                out.add(Der.explicit(3, Der.sequence(rebuilt)))
            } else {
                out.add(child.encoded) // issuerUniqueID / subjectUniqueID passthrough
            }
        }
        val newTbs = Der.sequence(out)

        val signature = CertificateHelper.sign(signerAlgorithm, keybox.keyPair.private, newTbs)
        val certificate =
            Der.sequence(newTbs, algorithmIdentifier, Der.bitStringNoUnused(signature))
        return CertificateHelper.decodeCertificate(certificate)
    }

    /**
     * Retrieves the signing KeyBox for a UID, choosing the key type from the original certificate's
     * signature algorithm (which may be a full name like "SHA256withRSA" or a bare key type).
     */
    private fun getKeyboxForUidAndAlgorithm(uid: Int, algorithm: String): KeyBox {
        val keyboxFile = ConfigurationManager.getKeyboxFileForUid(uid)
        val keyType =
            when {
                algorithm.contains("RSA", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_RSA
                algorithm.contains("EC", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_EC
                else -> algorithm
            }
        return KeyBoxManager.getAttestationKey(keyboxFile, keyType)
            ?: throw IllegalArgumentException(
                "No keybox found for UID $uid and algorithm '$keyType' (derived from input '$algorithm') in file $keyboxFile"
            )
    }
}
