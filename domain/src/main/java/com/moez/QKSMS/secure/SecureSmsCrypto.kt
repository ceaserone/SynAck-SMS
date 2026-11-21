package dev.octoshrimpy.quik.secure

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SynAck Secure SMS v1: P-256 ECDH + HKDF-SHA256 + AES-256-GCM.
 *
 * Pure JCA implementation. Never embed a shared decryption key in an APK.
 * The pairing keys MUST be compared over an independent channel before
 * enabling encryption, to prevent an SMS man-in-the-middle attack.
 *
 * v1 deliberately does not provide forward secrecy or post-compromise healing.
 * This is an experimental protocol, not an independently audited messenger.
 */
object SecureSmsCrypto {
    private val random = SecureRandom()
    private const val CONTEXT = "SynAck SMS ECDH AES-256-GCM v1"
    private const val AAD = "SynAck SMS encrypted text v1"
    private const val NONCE_LENGTH = 12
    private val allowedCurveParams: ECParameterSpec by lazy {
        (newIdentity().public as java.security.interfaces.ECPublicKey).params
    }

    fun newIdentity(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"), random)
            generateKeyPair()
        }

    fun decodePublic(bytes: ByteArray): PublicKey {
        require(bytes.size in 80..160) { "Unexpected public-key size" }
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
        val actual = (key as java.security.interfaces.ECPublicKey).params
        // AlgorithmParameters("EC") is Android API 26+. Derive the
        // canonical curve spec from KeyPairGenerator("EC") instead, which
        // works back to API 11 and keeps our minSdk 23 compatible.
        val expected = allowedCurveParams
        require(actual.order == expected.order &&
                actual.generator == expected.generator &&
                actual.cofactor == expected.cofactor &&
                actual.curve == expected.curve) {
            "Only P-256 public keys are accepted"
        }
        return key
    }

    private fun sortedKeyMaterial(a: PublicKey, b: PublicKey): ByteArray {
        val first = a.encoded
        val second = b.encoded
        val isFirstEarlier = compareBytes(first, second) <= 0
        val left = if (isFirstEarlier) first else second
        val right = if (isFirstEarlier) second else first
        return ByteBuffer.allocate(4 + left.size + right.size)
            .putInt(left.size).put(left).put(right).array()
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }

    /** The same code on both phones. Read it aloud to verify key ownership. */
    fun safetyCode(ours: PublicKey, theirs: PublicKey): String {
        val hash = MessageDigest.getInstance("SHA-256")
            .digest("SynAck SMS pairing code v1".toByteArray() + sortedKeyMaterial(ours, theirs))
        val text = hash.take(8).joinToString("") { "%02X".format(it.toInt() and 0xff) }
        return text.chunked(4).joinToString("-")
    }

    private fun deriveKey(privateKey: PrivateKey, ours: PublicKey, theirs: PublicKey): SecretKeySpec {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(theirs, true)
        val secret = agreement.generateSecret()

        val context = CONTEXT.toByteArray(Charsets.UTF_8)
        val salt = MessageDigest.getInstance("SHA-256")
            .digest(context + sortedKeyMaterial(ours, theirs))
        val extract = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(salt, "HmacSHA256"))
        }.doFinal(secret)
        secret.fill(0)
        // HKDF-Expand single block, 32 bytes output.
        val expand = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(extract, "HmacSHA256"))
        }.doFinal(context + byteArrayOf(1))
        extract.fill(0)
        return SecretKeySpec(expand.copyOf(32), "AES")
    }

    /** Returns nonce || authenticated ciphertext + tag, suitable for Base64 encoding. */
    fun encrypt(privateKey: PrivateKey, ours: PublicKey, theirs: PublicKey, plaintext: String): ByteArray {
        val nonce = ByteArray(NONCE_LENGTH).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(privateKey, ours, theirs), GCMParameterSpec(128, nonce))
        cipher.updateAAD(AAD.toByteArray(Charsets.UTF_8))
        return nonce + cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    }

    /** Rejects truncated, altered or wrong-key ciphertext via GCM tag validation. */
    fun decrypt(privateKey: PrivateKey, ours: PublicKey, theirs: PublicKey, payload: ByteArray): String {
        require(payload.size >= NONCE_LENGTH + 16) { "Ciphertext is too short" }
        require(payload.size <= 16 * 1024) { "Ciphertext exceeds maximum SMS payload" }
        val nonce = payload.copyOfRange(0, NONCE_LENGTH)
        val ciphertext = payload.copyOfRange(NONCE_LENGTH, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(privateKey, ours, theirs), GCMParameterSpec(128, nonce))
        cipher.updateAAD(AAD.toByteArray(Charsets.UTF_8))
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }
}
