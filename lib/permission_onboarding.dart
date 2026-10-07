// First-launch permission explanation and the "denied" dialogs (Task 9.2).
//
// Order: the explanation once, then READ_PHONE_STATE; location is asked only
// when the user turns "Share location" on. The answer to the explanation is
// stored, so it is shown once per install.
import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// SharedPreferences key of the stored answer: `continue` or `not_now`.
const permissionIntroKey = 'permission_intro_answer';

/// The stored answer, or `null` when the explanation has not been answered.
/// Replaceable in tests.
Future<String?> Function() readPermissionIntroAnswer =
    () async => (await SharedPreferences.getInstance()).getString(permissionIntroKey);

/// Stores the answer. Replaceable in tests.
Future<void> Function(String answer) savePermissionIntroAnswer =
    (answer) async => (await SharedPreferences.getInstance()).setString(permissionIntroKey, answer);

/// Opens this app's page in system settings. Replaceable in tests.
Future<bool> Function() openSettings = openAppSettings;

/// The first-launch explanation. Returns `true` for Continue, `false` for Not now.
class PermissionIntroDialog extends StatelessWidget {
  const PermissionIntroDialog({super.key});

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      key: const Key('permission-intro'),
      title: const Text('Permissions this app uses'),
      content: const SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Phone state', style: TextStyle(fontWeight: FontWeight.bold)),
            SizedBox(height: 4),
            Text('Lets the SIM change and Call during app use checks see whether the SIM was swapped '
                'or a call is active. The app does not read phone numbers, contacts or call content. '
                'Without it, those two checks show UNAVAILABLE.'),
            SizedBox(height: 12),
            Text('Location (optional)', style: TextStyle(fontWeight: FontWeight.bold)),
            SizedBox(height: 4),
            Text('Off until you switch on Share location in Trial checks. Only then does the app ask for '
                'it, use it for the Mock Location check and send it with the security events.'),
            SizedBox(height: 12),
            Text('Next, Android asks for Phone state.'),
          ],
        ),
      ),
      actions: [
        TextButton(
          key: const Key('permission-intro-not-now'),
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Not now'),
        ),
        FilledButton(
          key: const Key('permission-intro-continue'),
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Continue'),
        ),
      ],
    );
  }
}

/// `true` for an answer that leaves the permission off (denied, permanently
/// denied, restricted).
bool isRefused(PermissionStatus status) =>
    status.isDenied || status.isPermanentlyDenied || status.isRestricted;

/// Explains a refused permission and offers Open Settings. [what] names it
/// ("Phone state", "Location"); [effect] says what stays off.
Future<void> showPermissionRefusedDialog(
  BuildContext context, {
  required String what,
  required PermissionStatus status,
  required String effect,
}) {
  final permanently = status.isPermanentlyDenied || status.isRestricted;
  return showDialog<void>(
    context: context,
    builder: (context) => AlertDialog(
      key: const Key('permission-refused'),
      title: Text(permanently ? '$what is blocked' : '$what not granted'),
      content: Text(
        permanently
            ? '$effect Android will not ask again; turn it on in the app settings (Permissions).'
            : '$effect You can allow it later in the app settings, or try again from Trial checks.',
      ),
      actions: [
        TextButton(
          key: const Key('permission-refused-close'),
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
        FilledButton(
          key: const Key('permission-open-settings'),
          onPressed: () {
            Navigator.of(context).pop();
            openSettings();
          },
          child: const Text('Open Settings'),
        ),
      ],
    ),
  );
}
