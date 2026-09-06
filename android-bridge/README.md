# Android SMS bridge

Private/sideloaded Android transport for `harness-gateway`.

The app is deliberately **not an authority**. It has no GitHub credentials, repair-worker credentials, governance data, or policy data. It receives ordinary SMS, forwards an authenticated command to the gateway over HTTPS, and optionally relays the gateway's short response by SMS.

## Runtime flow

`Google Messages/SMS -> SmsReceiver -> HTTPS POST /sms/command -> gateway -> SMS reply`

The app sends the original sender identity as `X-SMS-Sender` and authenticates the device with `X-Gateway-Token`.

## Build

Open this directory as an Android Studio project or run Gradle with Android SDK 35 installed.

Before building, replace the placeholder values in `local.properties` or provide them through Gradle properties:

- `BRIDGE_ENDPOINT`
- `BRIDGE_TOKEN`
- `AUTHORIZED_PHONE`

Never commit real values.

## Permissions

The bridge requires SMS receive/send permissions. For a private/sideload deployment, install the APK directly on the controlled device. Google Play SMS permission/default-handler requirements are not part of this artifact.
