# Release signing key

Release builds of the trial apps (`rasp_trial` Flutter, `rasp_trial_rn` React
Native) are signed with the **debug key** until a release key is configured.
A debug-signed app can be rebuilt and re-signed by anyone, so the RASP
`tamper` / `repackage` checks only mean something with your own key.

**You create and keep the key.** If it is lost you can never update the app
under the same signature; if it leaks anyone can sign "your" app. Do not let
a tool, a chat or a CI log see the passwords.

## 1. Create the key (once)

Run in a terminal on your own machine (it asks for the passwords; use a
password manager):

```powershell
keytool -genkeypair -v -keystore "$HOME\rasp-keys\rasp-upload.jks" `
  -storetype PKCS12 -keyalg RSA -keysize 4096 -validity 10000 `
  -alias rasp-upload -dname "CN=<Company>, O=<Company>, C=IN"
```

Make the folder first (`mkdir $HOME\rasp-keys`). Keep the `.jks` **outside**
every git repository.

Back it up now: two copies in different places (e.g. company password
manager / vault + encrypted offline drive), together with both passwords.

## 2. Point the build at it

Either a file `android/key.properties` in each app (already git-ignored):

```properties
storeFile=C:/Users/<you>/rasp-keys/rasp-upload.jks
storePassword=<store password>
keyAlias=rasp-upload
keyPassword=<key password>
```

or environment variables (CI): `RASP_RELEASE_STORE_FILE`,
`RASP_RELEASE_STORE_PASSWORD`, `RASP_RELEASE_KEY_ALIAS`,
`RASP_RELEASE_KEY_PASSWORD`.

To make sure a release is never accidentally debug-signed, build with
`-PraspRequireReleaseKey=true`; the build then stops if no key is set:

```powershell
# Flutter
flutter build appbundle --release -P raspRequireReleaseKey=true
# React Native
cd android; .\gradlew.bat bundleRelease -PraspRequireReleaseKey=true
```

The Flutter build also prints `RASP build config (release): signing
certificate SHA-256 …` and writes it to `assets/generated/rasp_build.json`,
which the app uses as `expectedSigningCertSha256`.

## 3. With Google Play (Play App Signing)

The key above becomes your **upload key**. Google signs what users install
with its own **app signing key**. So:

- the fingerprint the app must expect on users' phones is the **app signing
  key certificate** SHA-256 from Play Console → App integrity → App signing;
- put that value in the dashboard (Security settings) and in the app's RASP
  config for Play builds;
- builds you install yourself (signed with the upload key) show the upload
  key's fingerprint instead — expected.

See also `BE/docs/PLAY_INTEGRITY_SETUP.md`, Step 4.

## 4. Check a built file

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\build-tools\36.0.0\apksigner.bat" verify --print-certs -v app-release.apk
```

`Signer #1 certificate SHA-256 digest` must be your key's (compare with
`keytool -list -v -keystore rasp-upload.jks`), not
`CN=Android Debug`.

## If the key leaks or is lost

- With Play App Signing: request an **upload key reset** in Play Console
  (App integrity → App signing); users are unaffected.
- Without Play App Signing: a lost key cannot be recovered; a leaked key
  needs key rotation (APK Signature Scheme v3) in a new release.
