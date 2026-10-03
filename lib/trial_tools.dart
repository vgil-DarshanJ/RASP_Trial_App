import 'package:permission_handler/permission_handler.dart' show PermissionStatus;
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLeanState;

/// SPKI pins typed into the Trial checks card: separated by commas, spaces or
/// new lines; a pin without the `sha256/` prefix gets it.
List<String> parsePins(String text) => [
      for (final pin in text.split(RegExp(r'[\s,]+')))
        if (pin.isNotEmpty) pin.startsWith('sha256/') ? pin : 'sha256/$pin',
    ];

/// Short label for the READ_PHONE_STATE status.
String phonePermissionLabel(PermissionStatus? status) => switch (status) {
      null => 'not checked yet',
      PermissionStatus.granted => 'granted',
      PermissionStatus.denied => 'not granted',
      PermissionStatus.permanentlyDenied => 'denied — allow it in app settings',
      PermissionStatus.restricted => 'restricted by the device',
      PermissionStatus.limited => 'limited',
      PermissionStatus.provisional => 'provisional',
    };

/// One detector's current verdict, e.g. `UNKNOWN (baseline stored)`.
String detectorVerdict(RaspLeanState state, String id) {
  final result = state.extendedDetectors[id];
  if (result == null) return 'no result yet';
  final reason = result.unavailableReason;
  return '${result.status.name.toUpperCase()}${reason == null ? '' : ' ($reason)'}';
}
