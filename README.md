# SynAck SMS

A privacy-focused Android SMS/MMS application maintained by SynAck Networks, forked from [QUIK](https://github.com/quik-sms/quik), itself based on QKSMS.

Also before I get started, well before you get started maybe both...originally I made this for my wife and I...I wanted something private that I could send messages to my wife throughout the day and have them encrypted and encrypted to the point where nothing sees this message except for your carrier and your carrier gets an encrypted message to pass off to the other person that means no connecting to Google to update the files needed or anything along those lines not once does this connect to anything to download anything or to save messages nothing all I can say is don't lose your original key or you're not reading those messages... also this is all beta until otherwise noted with that you can proceed!

## Current capabilities

- Regular SMS and carrier MMS, conversation management, notifications, scheduling and backups.
- On-device number blocking; third-party Call Control / Should I Answer integrations removed.
- Carrier MMS XML configurations bundled locally; the optional refresh is manual-only and requires review.
- Debug APK builds on source changes or manual request via GitHub Actions.

## Development status

**Experimental SynAck Secure Chat v1 code is included.** Verified one-to-one pairs can exchange authenticated encrypted SMS without a server. See [protocol and security limitations](security/SECURE_SMS_V1.md). This is **not independently audited or validated on two physical phones**, and must not be considered production-grade secure messaging yet.

## Security and compatibility

- Android application ID: `com.synack.sms` (debug: `com.synack.sms.debug`).
- Source code retains QUIK's original Java/Kotlin namespace for compatibility. The new application ID is a separate Android installation and does not migrate data from older QUIK packages.
- SMS/MMS databases, exported backups, permissions, dependency binaries and runtime behavior require continued privacy and security review.

## Open-source attribution

This project is based on QUIK/QKSMS and contains code by their respective contributors. Original license and copyright notices are retained. The distribution is subject to the GNU General Public License v3.0; see [LICENSE](LICENSE).

For bugs and feature requests, open a [GitHub issue](https://github.com/ceaserone/SynAck-SMS/issues).
