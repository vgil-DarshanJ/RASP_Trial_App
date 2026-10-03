// Trial checks helpers (Task 4.8). Real: lib/trial_tools.dart. No platform
// channel involved.
import 'package:flutter_test/flutter_test.dart';
import 'package:permission_handler/permission_handler.dart';
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
}
