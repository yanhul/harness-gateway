# Android SMS bridge

The phone is a transport adapter, not the authority.

## Required behavior

1. Receive an SMS in Google Messages' normal SMS transport.
2. Accept commands only from the configured human sender.
3. POST the command to `POST /sms/command` over HTTPS with `X-Gateway-Token`.
4. Include the sender identity as `X-SMS-Sender`.
5. Relay the gateway response back by SMS when configured.

## Security boundary

The Android app must contain no GitHub token, repository write token, repair-worker token, governance secret, or policy data. The server authenticates the Android bridge with a dedicated token; the server remains responsible for sender allowlisting, ticket state, nonce replay protection, exact SHA binding, and governance digest binding.

For a private/sideloaded gateway, Android SMS permissions can be used without making the gateway a public Play Store SMS app. If distributed through Google Play, current SMS permission/default-handler rules must be checked before deployment.
