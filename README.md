# FIDO2 PoC

Proof of concept implementation of the WebAuthn standard to provide passwordless and usernameless login to services.

## Demo

Demo is available on [https://fido.mxblue.net.au](https://fido.mxblue.net.au).

* Register with any username and display name.
  * A log message of `{"status":"ok"}` indicates successful registration.
* To try passwordless login, enter the registered username and click login.
  * A log message of `{"status":"ok", "user": <user object>}` indicates successful login.
* To try usernameless login, clear the username field and click login.
  * A prompt for selecting a set of credentials should appear.
  * A log message of `{"status":"ok", "user": <user object>}` indicates successful login. The user object should match the account matching the username and display name you registered the credential with.

## Usage

Read the READMEs in the frontend and backend folder to run your own instance.

## Notes

**Disclaimer: This is only based on my understanding of the WebAuthn spec, any corrections are welcome where needed.**

The backend is configured to perform authentication as a first factor (think replacement for passwords). This means that the server will always check that user verification has been performed. In order to not require user verification, switch the factor in the verification stages of registration and login to second factor or either instead, which will allow the platform to only check for presence.

Usernameless login does not work with roaming authenticators (FIDO2 keys) at moment, the backend encounters an error on login.