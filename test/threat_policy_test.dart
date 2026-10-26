// Trial app reaction policy (Task 4.7 item 1): developer options, USB
// debugging and USB only produce warnings; closing the app needs the
// off-by-default setting. Real: postureWarnings and shouldCloseApp with real
// RaspLeanState values. No platform channel involved.
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/core/core.dart';
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

RaspLeanState _wifi(DetectionStatus status, {bool onWifi = true, String? type, List<String> signals = const []}) =>
    RaspLeanState(
      screenshotActive: true,
      usb: RaspUsbState.unsupported,
      clipboardActive: true,
      clipboardEvidence: RaspClipboardEvidence.unsupported,
      extendedDetectors: {
        'unsafe_wifi': DetectionResult(
          detectorId: 'unsafe_wifi',
          detectorType: DetectorType.custom,
          category: ThreatCategory.networkSecurity,
          status: status,
          severity: DetectionSeverity.medium,
          title: 'Unsafe Wi-Fi',
          description: '',
          observedAt: DateTime.utc(2026),
          evidence: [
            for (final s in signals) DetectionEvidence(key: 'wifi_signal', value: s),
            DetectionEvidence(key: 'on_wifi', value: onWifi),
            DetectionEvidence(key: 'security_type', value: type),
          ],
        ),
      },
    );

void main() {
  group('unsafe Wi-Fi', () {
    final open = _wifi(DetectionStatus.detected, type: 'OPEN', signals: ['open_network']);
    final wpa = _wifi(DetectionStatus.secure, type: 'PSK');
    final data = _wifi(DetectionStatus.secure, onWifi: false);

    test('banner line while DETECTED, none on a secured network', () {
      expect(postureWarnings(open), ['Unsafe Wi-Fi network: it has no password, so people nearby can read the traffic.']);
      expect(postureWarnings(wpa), isEmpty);
    });

    test('unsafe alert when it becomes DETECTED (also at the first reading), not again while it stays', () {
      expect(wifiChangeAlert(null, open)?.unsafe, isTrue);
      expect(wifiChangeAlert(wpa, open)?.unsafe, isTrue);
      expect(wifiChangeAlert(open, open), isNull);
    });

    test('notice with the security type on joining a secured Wi-Fi, nothing on mobile data or while staying', () {
      expect(wifiChangeAlert(data, wpa), (message: 'Connected to Wi-Fi (PSK).', unsafe: false));
      expect(wifiChangeAlert(wpa, wpa), isNull);
      expect(wifiChangeAlert(wpa, data), isNull);
      expect(wifiChangeAlert(null, _state()), isNull);
    });
  });

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
