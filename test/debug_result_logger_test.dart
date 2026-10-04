// Debug-only RASP_RESULT logger (Task 5.0 item 3).
// Real: DebugResultLogger, the dashboard and RaspLeanSession state decoding.
// Fake: the native side (test/support/fake_native.dart), which records what
// the app sends on the RASP_RESULT logcat channel. Not exercised: the native
// Log.i call (android/app/src/debug) — checked on the phone with adb logcat.
import 'dart:convert';

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLeanState;
import 'package:rasp_shield/sdk/security_controls.dart' show RaspClipboardEvidence, RaspUsbState;
import 'package:rasp_trial/debug_result_logger.dart';

import 'support/fake_native.dart';

void main() {
  test('one JSON line per result: id, status, reason, evidence names and values', () async {
    final lines = <String>[];
    final logger = DebugResultLogger(sink: (line) async => lines.add(line));
    const state = RaspLeanState(
      screenshotActive: true,
      usb: RaspUsbState(supported: true, usbConnected: false, usbDebuggingEnabled: true, developerModeEnabled: true, connectedDeviceCount: 0),
      clipboardActive: true,
      clipboardEvidence: RaspClipboardEvidence.unsupported,
    );
    logger.log(state);
    final byId = {for (final l in lines) (jsonDecode(l) as Map)['id']: jsonDecode(l) as Map};
    expect(byId.keys, containsAll(['screenshot_protection', 'usb_connection', 'adb_enabled', 'clipboard_protection']));
    expect(byId['adb_enabled']!['status'], 'ON');
    expect(byId['usb_connection']!['status'], 'OFF');

    lines.clear();
    logger.log(state);
    expect(lines, isEmpty, reason: 'nothing changed, nothing logged');
  });

  testWidgets('the app logs each detector result once, then only changes', (tester) async {
    expect(kDebugMode, isTrue);
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState(detectors: {
      'hook_detection': {
        'detectorId': 'hook_detection', 'status': 'DETECTED', 'reason': null, 'observedAtMillis': 0,
        'evidence': [
          {'key': 'detected_by', 'value': ['hook_framework_lib'], 'note': null},
          {'key': 'hook_signal_line', 'value': '7f0000-7f1000 r-xp 00000000 fd:00 1 /data/adb/lspd/lib/liblspd.so', 'note': 'hook_framework_lib'},
        ],
      },
      'vpn': nativeCheck('vpn', 'SECURE'),
    }));
    final hook = native.resultLogLines.map((l) => jsonDecode(l) as Map).firstWhere((m) => m['id'] == 'hook_detection');
    expect(hook['status'], 'DETECTED');
    expect(hook['evidence'], [
      {'key': 'detected_by', 'value': ['hook_framework_lib'], 'note': null},
      {'key': 'hook_signal_line', 'value': '7f0000-7f1000 r-xp 00000000 fd:00 1 /data/adb/lspd/lib/liblspd.so', 'note': 'hook_framework_lib'},
    ]);

    final before = native.resultLogLines.length;
    await emitState(tester, native, nativeState(detectors: {
      'hook_detection': {
        'detectorId': 'hook_detection', 'status': 'DETECTED', 'reason': null, 'observedAtMillis': 5,
        'evidence': [
          {'key': 'detected_by', 'value': ['hook_framework_lib'], 'note': null},
          {'key': 'hook_signal_line', 'value': '7f0000-7f1000 r-xp 00000000 fd:00 1 /data/adb/lspd/lib/liblspd.so', 'note': 'hook_framework_lib'},
        ],
      },
      'vpn': nativeCheck('vpn', 'DETECTED'),
    }));
    final added = native.resultLogLines.sublist(before).map((l) => (jsonDecode(l) as Map)['id']).toList();
    expect(added, ['vpn'], reason: 'only the changed result (a new observation time alone is not a change)');
  });
}
