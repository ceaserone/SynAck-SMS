package dev.octoshrimpy.quik.secure

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telephony.PhoneNumberUtils
import android.telephony.SmsManager
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Experimental SynAck Secure Chat v1.
 *
 * The locally generated EC private key is encrypted at rest with a
 * non-exportable Android Keystore AES key (Android 6.0+). Public keys travel
 * over carrier SMS. NEVER trust them until users compare the safety code over
 * an independent channel. Static ECDH v1 does NOT offer forward secrecy.
 */
object SecureSms {
    enum class State { NONE, INVITED, PENDING, UNVERIFIED, VERIFIED }

    private const val STORAGE = "synack_secure_sms_v1"
    private const val MASTER_ALIAS = "synack_sms_identity_wrapping_key_v1"
    private const val PRIVATE = "identity_private"
    private const val PUBLIC = "identity_public"
    private const val INVITE = "SYNK1:"
    private const val REPLY = "SYNK2:"
    private const val DATA = "SYN2:"
    private val lock = Any()
    @Volatile private var app: Context? = null

    fun initialize(context: Context) { app = context.applicationContext }

    private fun context(): Context =
        app ?: throw IllegalStateException("Secure Chat has not been initialized")

    private fun store(): SharedPreferences =
        context().getSharedPreferences(STORAGE, Context.MODE_PRIVATE)

    private fun contactId(address: String): String {
        val region = Locale.getDefault().country.ifBlank { "US" }
        val normalized = PhoneNumberUtils.formatNumberToE164(address, region)
            ?: PhoneNumberUtils.normalizeNumber(address)
        require(normalized.isNotBlank()) { "A phone number is required" }
        return MessageDigest.getInstance("SHA-256")
            .digest(normalized.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun entry(name: String, address: String): String =
        name + ":" + contactId(address)

    private fun encode(bytes: ByteArray) =
        Base64.encodeToString(bytes, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)

    private fun decode(value: String): ByteArray {
        require(value.length <= 20000) { "Oversize packet" }
        return Base64.decode(value, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)
    }

    private fun wrappingKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(MASTER_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(MASTER_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build())
        return generator.generateKey()
    }

    private fun identity(): KeyPair = synchronized(lock) {
        val prefs = store()
        val publicText = prefs.getString(PUBLIC, null)
        val privateText = prefs.getString(PRIVATE, null)

        if (publicText != null || privateText != null) {
            // Identity corruption must never cause silent rekeying.
            check(publicText != null && privateText != null) {
                "Secure identity incomplete: restore or reset manually."
            }
            val saved = decode(privateText!!)
            require(saved.size >= 28) { "Corrupted encrypted identity" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrappingKey(),
                GCMParameterSpec(128, saved.copyOfRange(0, 12)))
            val plaintext = cipher.doFinal(saved.copyOfRange(12, saved.size))
            val privateKey = try {
                KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(plaintext))
            } finally {
                plaintext.fill(0)
            }
            return@synchronized KeyPair(
                SecureSmsCrypto.decodePublic(decode(publicText!!)), privateKey)
        }

        val pair = SecureSmsCrypto.newIdentity()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        val wrapped = cipher.iv + cipher.doFinal(pair.private.encoded)
        check(prefs.edit()
            .putString(PUBLIC, encode(pair.public.encoded))
            .putString(PRIVATE, encode(wrapped))
            .commit()) { "Could not persist secure identity" }
        pair
    }

    private fun peer(address: String): PublicKey? =
        store().getString(entry("peer", address), null)
            ?.let { SecureSmsCrypto.decodePublic(decode(it)) }

    private fun pending(address: String): PublicKey? =
        store().getString(entry("pending", address), null)
            ?.let { SecureSmsCrypto.decodePublic(decode(it)) }

    fun state(address: String): State = synchronized(lock) {
        when {
            store().getBoolean(entry("verified", address), false) -> State.VERIFIED
            peer(address) != null -> State.UNVERIFIED
            pending(address) != null -> State.PENDING
            store().getBoolean(entry("invited", address), false) -> State.INVITED
            else -> State.NONE
        }
    }

    fun isVerified(address: String) = state(address) == State.VERIFIED
    fun isProtected(address: String) = state(address) != State.NONE

    fun sendBlockReason(addresses: Collection<String>, attachments: Int, delay: Int = 0): String? {
        val protected = addresses.filter(::isProtected)
        if (protected.isEmpty()) return null
        if (addresses.size != 1 || attachments != 0 || delay != 0)
            return "Secure Chat supports immediate, one-to-one text SMS only."
        if (!isVerified(protected.single()))
            return "Secure pairing not verified. Compare safety codes before messaging."
        return null
    }

    fun safetyCode(address: String): String? = synchronized(lock) {
        val remote = peer(address) ?: return@synchronized null
        SecureSmsCrypto.safetyCode(identity().public, remote)
    }

    @Suppress("DEPRECATION")
    private fun sendControl(address: String, packet: String, subscriptionId: Int) {
        val manager = if (subscriptionId >= 0)
            SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
        else SmsManager.getDefault()
        val parts = manager.divideMessage(packet)
        if (parts.size == 1)
            manager.sendTextMessage(address, null, packet, null, null)
        else manager.sendMultipartTextMessage(address, null, parts, null, null)
    }

    fun invite(address: String, subscriptionId: Int = -1) = synchronized(lock) {
        check(state(address) == State.NONE) { "Reset old pairing to start over." }
        sendControl(address, INVITE + encode(identity().public.encoded), subscriptionId)
        store().edit().putBoolean(entry("invited", address), true).apply()
    }

    fun accept(address: String, subscriptionId: Int = -1) = synchronized(lock) {
        check(state(address) == State.PENDING) { "No pending invitation" }
        val remote = pending(address) ?: throw IllegalStateException("No public key to accept")
        sendControl(address, REPLY + encode(identity().public.encoded), subscriptionId)
        store().edit()
            .putString(entry("peer", address), encode(remote.encoded))
            .remove(entry("pending", address))
            .putBoolean(entry("verified", address), false)
            .apply()
    }

    fun verify(address: String) = synchronized(lock) {
        check(state(address) == State.UNVERIFIED) { "No exchanged keys to verify" }
        check(peer(address) != null)
        store().edit().putBoolean(entry("verified", address), true).apply()
    }

    fun reset(address: String) = synchronized(lock) {
        store().edit()
            .remove(entry("peer", address))
            .remove(entry("pending", address))
            .remove(entry("invited", address))
            .remove(entry("verified", address))
            .remove(entry("seen", address))
            .apply()
    }

    fun encrypt(address: String, text: String): String = synchronized(lock) {
        check(isVerified(address)) { "Secure Chat not verified" }
        val ours = identity()
        val remote = peer(address) ?: throw IllegalStateException("Missing recipient public key")
        DATA + encode(SecureSmsCrypto.encrypt(ours.private, ours.public, remote, text))
    }

    fun isCiphertext(text: String) = text.startsWith(DATA)

    /** Validate the GCM tag, not merely the SYN2 prefix. */
    private fun decryptVerified(address: String, wire: String): String {
        require(isCiphertext(wire) && isVerified(address))
        val ours = identity()
        val remote = peer(address) ?: throw IllegalStateException("Unknown peer")
        return SecureSmsCrypto.decrypt(ours.private, ours.public, remote,
            decode(wire.removePrefix(DATA)))
    }

    fun isAuthenticatedCiphertext(address: String, wire: String): Boolean {
        return try {
            decryptVerified(address, wire)
            true
        } catch (_: Exception) {
            false
        }
    }

    fun forDisplay(address: String, wire: String): String {
        if (!isCiphertext(wire)) return wire
        if (!isVerified(address)) return "[Secure message — verify pairing to read]"
        return try {
            decryptVerified(address, wire)
        } catch (_: Exception) {
            "[Secure message — authentication failed or keys unavailable]"
        }
    }

    fun forSummary(wire: String): String =
        if (isCiphertext(wire)) "🔐 SynAck encrypted message" else wire

    /**
     * Returns a locally visible marker for key exchanges; incoming raw keys
     * are NOT saved to the SMS database. Null drops authenticated replays.
     * Invalid encrypted packets remain ciphertext and never become plaintext.
     */
    fun handleIncoming(address: String, wire: String): String? = synchronized(lock) {
        if (wire.startsWith(INVITE) || wire.startsWith(REPLY)) {
            val invitation = wire.startsWith(INVITE)
            val pub = try {
                val encoded = wire.substringAfter(':')
                require(encoded.length in 20..400)
                SecureSmsCrypto.decodePublic(decode(encoded))
            } catch (_: Exception) {
                return@synchronized "⚠ Invalid SynAck Secure Chat key exchange"
            }

            if (state(address) == State.VERIFIED)
                return@synchronized "⚠ Unrequested new key ignored; established key unchanged"
            if (invitation) {
                store().edit().putString(entry("pending", address), encode(pub.encoded)).apply()
                return@synchronized "🔐 Secure Chat invitation. Open Secure Chat in this conversation to accept."
            }
            if (state(address) != State.INVITED)
                return@synchronized "⚠ Unrequested Secure Chat response ignored"
            store().edit()
                .putString(entry("peer", address), encode(pub.encoded))
                .remove(entry("invited", address))
                .remove(entry("pending", address))
                .putBoolean(entry("verified", address), false)
                .apply()
            return@synchronized "🔐 Secure Chat reply received. Compare safety codes to enable."
        }

        if (!isCiphertext(wire)) {
            // A verified contact can still send regular carrier SMS from another
            // app. Make the downgrade obvious rather than implying it was secure.
            return@synchronized if (isVerified(address))
                "⚠ Unencrypted SMS from a paired contact:\n" + wire
            else wire
        }
        if (!isVerified(address)) return@synchronized wire
        // Authenticate before recording a replay nonce. Never log plaintext.
        if (!isAuthenticatedCiphertext(address, wire)) return@synchronized wire
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(wire.toByteArray(Charsets.UTF_8)).take(12)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val seen = store().getString(entry("seen", address), "")!!
            .split(',').filter { it.isNotBlank() }
        if (fingerprint in seen) return@synchronized null
        store().edit().putString(entry("seen", address),
            (seen.takeLast(255) + fingerprint).joinToString(",")).apply()
        wire
    }
}
