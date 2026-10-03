// Trial app reaction policy (Task 4.7 item 1): developer options, USB
// debugging and USB only produce warnings; closing the app needs the
// off-by-default setting. Real: postureWarnings and shouldCloseApp with real
// RaspLeanState values. No platform channel involved.
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLeanState;
import 'package:rasp_shield/sdk/security_controls.dart' show RaspClipboardEvidence, RaspUsbState;
import 'package:rasp_trial/threat_policy.dart';

RaspLeanState _state({bool? devMode, bool? adb, bool? usb}) => RaspLeanState(
      screenshotActive: true,
      usb: RaspUsbState(
        supported: true,
        usbConnected: usb,
        usbDebuggingEnabled: adb,
        developerModeEnabled: devMode,
        connectedDeviceCount: 0,
      ),
      clipboardActive: true,
      clipboardEvidence: RaspClipboardEvidence.unsupported,
    );

void main() {
  group('postureWarnings', () {
    test('one warning each for developer options, ADB and USB', () {
      expect(postureWarnings(_state(devMode: true, adb: true, usb: true)), [
        'Developer options are unlocked on this device.',
        'USB debugging (ADB) is enabled.',
        'A USB cable or dock is connected.',
      ]);
    });

    test('no warning when all three are off', () {
      expect(postureWarnings(_state(devMode: false, adb: false, usb: false)), isEmpty);
    });

    test('values that could not be read give no warning (the USB card shows Unknown)', () {
      expect(postureWarnings(_state()), isEmpty);
    });
  });

  group('shouldCloseApp', () {
    final off = _state(devMode: false, adb: false, usb: false);
    final on = _state(devMode: true, adb: true, usb: true);

    test('setting off (the default): never closes, also when ADB turns on or is on at start', () {
      expect(shouldCloseApp(previous: off, current: on, closeOnUsbDebugging: false), isFalse);
      expect(shouldCloseApp(previous: null, current: on, closeOnUsbDebugging: false), isFalse);
    });

    test('setting on: closes when ADB turns on, or is on at the first reading', () {
      expect(shouldCloseApp(previous: off, current: on, closeOnUsbDebugging: true), isTrue);
      expect(shouldCloseApp(previous: null, current: on, closeOnUsbDebugging: true), isTrue);
    });

    test('setting on: no close while ADB stays on, for developer options or USB alone, or for unknown ADB', () {
      expect(shouldCloseApp(previous: on, current: on, closeOnUsbDebugging: true), isFalse);
      expect(
        shouldCloseApp(previous: off, current: _state(devMode: true, adb: false, usb: true), closeOnUsbDebugging: true),
        isFalse,
      );
      expect(shouldCloseApp(previous: off, current: _state(), closeOnUsbDebugging: true), isFalse);
    });
  });
}
