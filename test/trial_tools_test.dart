// Trial checks helpers (Task 4.8; location heartbeat label: Task 9.3).
// Real: lib/trial_tools.dart. No platform channel involved.
import 'package:flutter_test/flutter_test.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:rasp_shield/sdk/lean_session.dart';
import 'package:rasp_trial/trial_tools.dart';

void main() {
  test('pins: comma, space or new-line separated; sha256/ added when missing', () {
    expect(parsePins('AAAA, sha256/BBBB\nCCCC  '), ['sha256/AAAA', 'sha256/BBBB', 'sha256/CCCC']);
    expect(parsePins('   '), isEmpty);
  });

  test('phone permission labels', () {
    expect(phonePermissionLabel(null), 'not checked yet');
    expect(phonePermissionLabel(PermissionStatus.granted), 'granted');
    expect(phonePermissionLabel(PermissionStatus.denied), 'not granted');
    expect(phonePermissionLabel(PermissionStatus.permanentlyDenied), contains('app settings'));
  });

  test('location heartbeat labels: each delivery result, the sharing-off message, none yet', () {
    final at = DateTime(2026, 10, 7, 12, 0, 5);
    RaspLocationHeartbeatStatus status(RaspLocationHeartbeatOutcome outcome, String detail, {bool cleared = false}) =>
        RaspLocationHeartbeatStatus(at: at, outcome: outcome, detail: detail, cleared: cleared);
    expect(locationHeartbeatLabel(status(RaspLocationHeartbeatOutcome.delivered, 'delivered'), sharing: true),
        'Location heartbeat at 12:00:05: delivered');
    expect(locationHeartbeatLabel(status(RaspLocationHeartbeatOutcome.rejected, 'HTTP 401'), sharing: true),
        'Location heartbeat at 12:00:05: rejected: HTTP 401');
    expect(
        locationHeartbeatLabel(
            status(RaspLocationHeartbeatOutcome.notDelivered, 'no answer from the backend (network or registration)'),
            sharing: true),
        'Location heartbeat at 12:00:05: not delivered: no answer from the backend (network or registration)');
    expect(locationHeartbeatLabel(status(RaspLocationHeartbeatOutcome.notConfigured, 'no backend credential'), sharing: true),
        'Location heartbeat at 12:00:05: not sent: no backend credential');
    expect(locationHeartbeatLabel(status(RaspLocationHeartbeatOutcome.delivered, 'delivered', cleared: true), sharing: false),
        'Sharing-off message at 12:00:05: delivered (backend location cleared)');
    expect(locationHeartbeatLabel(null, sharing: true), startsWith('Location heartbeat: not sent yet'));
    expect(locationHeartbeatLabel(null, sharing: false), 'Location heartbeat: off.');
  });
}
