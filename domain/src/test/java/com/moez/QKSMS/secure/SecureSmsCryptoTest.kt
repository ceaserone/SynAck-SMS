package dev.octoshrimpy.quik.secure

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureSmsCryptoTest {
    @Test
    fun twoPhonesAgreeOnCodeAndDecryptTheSameMessage() {
        val alice = SecureSmsCrypto.newIdentity()
        val bob = SecureSmsCrypto.newIdentity()
        val message = "Hello from SynAck SMS. 🔐 Unicode works."
        assertEquals(
            SecureSmsCrypto.safetyCode(alice.public, bob.public),
            SecureSmsCrypto.safetyCode(bob.public, alice.public)
        )
        val wire = SecureSmsCrypto.encrypt(alice.private, alice.public, bob.public, message)
        assertEquals(message,
            SecureSmsCrypto.decrypt(bob.private, bob.public, alice.public, wire))
        assertEquals(message,
            SecureSmsCrypto.decrypt(alice.private, alice.public, bob.public, wire))
        // Every message gets an independent 96-bit random nonce.
        val second = SecureSmsCrypto.encrypt(alice.private, alice.public, bob.public, message)
        assertTrue(!wire.contentEquals(second))
    }

    @Test
    fun tamperingWithCiphertextOrUsingTheWrongPrivateKeyFailsClosed() {
        val alice = SecureSmsCrypto.newIdentity()
        val bob = SecureSmsCrypto.newIdentity()
        val mallory = SecureSmsCrypto.newIdentity()
        val wire = SecureSmsCrypto.encrypt(alice.private, alice.public, bob.public, "Secret")

        val altered = wire.clone()
        altered[altered.lastIndex] = (altered.last().toInt() xor 1).toByte()
        var tamperRejected = false
        try {
            SecureSmsCrypto.decrypt(bob.private, bob.public, alice.public, altered)
        } catch (_: Exception) {
            tamperRejected = true
        }
        assertTrue("GCM authentication must reject modified ciphertext", tamperRejected)

        var wrongKeyRejected = false
        try {
            SecureSmsCrypto.decrypt(mallory.private, mallory.public, alice.public, wire)
        } catch (_: Exception) {
            wrongKeyRejected = true
        }
        assertTrue("Unpaired phone must not decrypt", wrongKeyRejected)
        assertNotEquals(
            SecureSmsCrypto.safetyCode(alice.public, bob.public),
            SecureSmsCrypto.safetyCode(alice.public, mallory.public)
        )
    }
}
