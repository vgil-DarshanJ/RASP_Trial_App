import 'package:permission_handler/permission_handler.dart' show PermissionStatus;
import 'package:rasp_shield/sdk/lean_session.dart'
    show RaspLeanState, RaspLocationHeartbeatOutcome, RaspLocationHeartbeatStatus;

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

/// Delivery result of the last location heartbeat, e.g.
/// `Location heartbeat at 12:00:05: delivered`. [sharing]: the Share
/// location switch, for the text before the first heartbeat.
String locationHeartbeatLabel(RaspLocationHeartbeatStatus? status, {required bool sharing}) {
  if (status == null) {
    return sharing
        ? 'Location heartbeat: not sent yet (after the first fix, then every 60 s).'
        : 'Location heartbeat: off.';
  }
  String two(int n) => n.toString().padLeft(2, '0');
  final at = status.at;
  final time = '${two(at.hour)}:${two(at.minute)}:${two(at.second)}';
  final what = status.cleared ? 'Sharing-off message' : 'Location heartbeat';
  final result = switch (status.outcome) {
    RaspLocationHeartbeatOutcome.delivered => status.cleared ? 'delivered (backend location cleared)' : 'delivered',
    RaspLocationHeartbeatOutcome.rejected => 'rejected: ${status.detail}',
    RaspLocationHeartbeatOutcome.notDelivered => 'not delivered: ${status.detail}',
    RaspLocationHeartbeatOutcome.notConfigured => 'not sent: ${status.detail}',
  };
  return '$what at $time: $result';
}

/// One detector's current verdict, e.g. `UNKNOWN (baseline stored)`.
String detectorVerdict(RaspLeanState state, String id) {
  final result = state.extendedDetectors[id];
  if (result == null) return 'no result yet';
  final reason = result.unavailableReason;
  return '${result.status.name.toUpperCase()}${reason == null ? '' : ' ($reason)'}';
}
