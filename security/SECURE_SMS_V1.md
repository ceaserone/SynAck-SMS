# SynAck SMS Secure Chat v1 — EXPERIMENTAL

**Not independently audited. Do not rely on this prototype for sensitive communication until two-device testing and a security review are complete.**

## How it works

- Open a one-to-one SMS conversation on **both phones**, each with SynAck SMS installed and configured as the default SMS app.
- On phone A, choose **Secure Chat (pair / verify)** → Send pairing SMS.
- On phone B, open the same conversation and choose Secure Chat → Accept and reply.
- On both phones, open Secure Chat and compare the entire safety code in person or over a separate live phone call. The codes MUST match exactly. Only then click **Codes match — enable** on each phone.
- Subsequent one-to-one text SMS messages are sent as `SYN2:` followed by authenticated ciphertext. The display layer decrypts transiently; the Android SMS provider and app Realm database store ciphertext.
- A normal SMS client sees only the encrypted payload. Neither phone needs an internet connection or QR scan for pairing.

## Protocol

- Public-key exchange: `SYNK1:<Base64URL X509 P-256 key>` / `SYNK2:<Base64URL X509 P-256 key>` over ordinary SMS.
- Key agreement: P-256 ECDH using unique app-installation identity keys.
- Derivation: HKDF-SHA256 with ordered public keys and protocol context.
- Encryption: AES-256-GCM with 96-bit random nonce and 128-bit tag.
- Public-key identity: safety code derived from both public keys; **user must verify independently**, because carrier SMS is not an authenticated key-exchange channel.
- Private identity: locally generated software EC key wrapped using Android Keystore AES-GCM; private keys are never included in APK source or a universal embedded secret.
- Replays: short hashes of the last 256 successfully authenticated incoming wire messages are retained in app-private preferences.
- One-to-one, immediate text only. No groups, file attachments, MMS or scheduled messages in encrypted mode. Failure must not fall back to plaintext.
- Debug APK uses a separate app data store and will not automatically share keys with release builds.

## Limitations and cautions

- **No forward secrecy**: compromise of the long-lived private identity might permit decryption of previously captured messages.
- No independent cryptographic audit, phone-to-phone integration tests, SIM compatibility tests, or defense against an already compromised phone.
- Verizon and other carriers can still see phone numbers, delivery times, approximate ciphertext sizes and routing metadata. Some network/system components may retain the encrypted texts.
- SMS multipart delivery adds length and carrier charges. If your phone cannot reassemble multipart SMS, decryption fails.
- Android cannot prevent screenshots or plaintext being revealed by other software with access to the unlocked device, accessibility services, or compromised OS. Notification previews intentionally show a generic encrypted-message label.
- Other app functions (copy, share, text-to-speech, screenshots, or unencrypted messaging outside a verified contact) can reveal plaintext by user action.
- Resetting a peer's key may make old ciphertext undecryptable. Losing the Android Keystore key or reinstalling the app may make old ciphertext undecryptable.
- Only on-device SMS sends routed through this app's message repository are protected; any external app or system SMS sender should be tested before relying on it.
- The first prototype has no secure key backup/export, and local Secure Chat preferences are excluded from Android auto backup via `allowBackup=false`.

The project remains under GPLv3 and includes original QUIK/QKSMS source notices.
