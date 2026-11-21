# Contributing to SynAck SMS

SynAck SMS is developed from the open-source QUIK/QKSMS Android messaging project.

## Report issues
Open an issue at https://github.com/ceaserone/SynAck-SMS/issues and include:
- Your SynAck SMS version (and whether it is the debug build).
- Android version, reproducible steps and what you expected to happen.
- Relevant *redacted* logs. Never post actual SMS contents, phone numbers, or contacts publicly.

## Send code changes
1. Create a branch and make a focused change.
2. Build the debug APK: `./gradlew :presentation:assembleDebug` (JDK 17 and Android SDK 34).
3. Test SMS/MMS behavior on a test device as appropriate.
4. Open a pull request with a short description and test results.

## Branding and source compatibility
The installed package ID is `com.synack.sms` (`com.synack.sms.debug` for debug builds).
Java and Kotlin source packages currently use `dev.octoshrimpy.quik`. That is intentional; do not rename these packages without a complete refactor and full test suite.

## Upstream
The project retains upstream contributor copyright notices and is subject to GPLv3. Original work:
- https://github.com/quik-sms/quik
