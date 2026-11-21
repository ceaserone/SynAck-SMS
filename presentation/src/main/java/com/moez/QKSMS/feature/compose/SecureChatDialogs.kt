package dev.octoshrimpy.quik.feature.compose

import android.app.Activity
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import dev.octoshrimpy.quik.secure.SecureSms

/**
 * One-time SMS pairing, with independent safety-code verification before
 * activating encryption. Pairing requires no camera or server.
 */
object SecureChatDialogs {
    fun show(activity: Activity, address: String, subId: Int, onChanged: () -> Unit) {
        try {
            when (SecureSms.state(address)) {
                SecureSms.State.NONE ->
                    AlertDialog.Builder(activity)
                        .setTitle("🔐 Start Secure Chat")
                        .setMessage("Send an SMS containing only your public key. The other " +
                            "phone needs SynAck SMS. You must compare the security code in " +
                            "person or by a separate phone call before encrypted texts are enabled.")
                        .setPositiveButton("Send pairing SMS") { _, _ ->
                            execute(activity, onChanged) { SecureSms.invite(address, subId) }
                        }
                        .setNegativeButton("Cancel", null).show()

                SecureSms.State.PENDING ->
                    AlertDialog.Builder(activity)
                        .setTitle("🔐 Invitation received")
                        .setMessage("Accept the public-key invitation and send your key back " +
                            "by ordinary SMS. Secure texting stays disabled until both " +
                            "phones compare and verify the safety code.")
                        .setPositiveButton("Accept and reply") { _, _ ->
                            execute(activity, onChanged) { SecureSms.accept(address, subId) }
                        }
                        .setNegativeButton("Cancel", null).show()

                SecureSms.State.INVITED ->
                    AlertDialog.Builder(activity)
                        .setTitle("🔐 Waiting for reply")
                        .setMessage("Your key invitation was sent. On the other phone, " +
                            "open this conversation and choose Secure Chat → Accept and reply.")
                        .setPositiveButton("OK", null)
                        .setNeutralButton("Cancel pairing") { _, _ ->
                            confirmReset(activity, address, onChanged)
                        }
                        .show()

                SecureSms.State.UNVERIFIED -> {
                    val code = SecureSms.safetyCode(address)
                        ?: throw IllegalStateException("Safety code is unavailable")
                    AlertDialog.Builder(activity)
                        .setTitle("🔐 Verify safety code")
                        .setMessage("Security code:\n\n" + code +
                            "\n\nCompare it aloud, IN PERSON or over a separate phone call. " +
                            "It must match the code on the other SynAck SMS phone exactly. " +
                            "Never use this SMS conversation to confirm the code.")
                        .setPositiveButton("Codes match — enable") { _, _ ->
                            execute(activity, onChanged) { SecureSms.verify(address) }
                        }
                        .setNegativeButton("Not verified", null)
                        .setNeutralButton("Reset") { _, _ ->
                            confirmReset(activity, address, onChanged)
                        }
                        .show()
                }

                SecureSms.State.VERIFIED ->
                    AlertDialog.Builder(activity)
                        .setTitle("🔒 Secure Chat ON")
                        .setMessage("New one-to-one text messages to this person are encrypted " +
                            "before they reach the SMS database or the carrier.\n\n" +
                            "Safety code: " + SecureSms.safetyCode(address) +
                            "\n\nExperimental v1; no forward secrecy or independent audit. " +
                            "Groups, attachments and delayed sending are disabled for this contact.")
                        .setPositiveButton("Done", null)
                        .setNeutralButton("Reset pairing") { _, _ ->
                            confirmReset(activity, address, onChanged)
                        }
                        .show()
            }
        } catch (error: Exception) {
            notifyError(activity, error)
        }
    }

    private fun confirmReset(activity: Activity, address: String, onChanged: () -> Unit) {
        AlertDialog.Builder(activity)
            .setTitle("Reset Secure Chat?")
            .setMessage("This removes this contact's public key and disables encryption. " +
                "Previously encrypted messages may become unreadable. " +
                "Future texts will be ordinary SMS unless you pair again.")
            .setPositiveButton("Reset") { _, _ ->
                execute(activity, onChanged) { SecureSms.reset(address) }
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun execute(activity: Activity, onChanged: () -> Unit, task: () -> Unit) {
        try {
            task()
            onChanged()
            Toast.makeText(activity, "Secure Chat status updated", Toast.LENGTH_SHORT).show()
        } catch (error: Exception) {
            notifyError(activity, error)
        }
    }

    private fun notifyError(activity: Activity, error: Exception) {
        Toast.makeText(activity, "Secure Chat: " + (error.message ?: "operation failed"),
            Toast.LENGTH_LONG).show()
    }
}
