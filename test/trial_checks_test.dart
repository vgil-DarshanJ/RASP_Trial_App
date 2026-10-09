// Trial checks card (Task 4.8, trial app side), driven through the real
// dashboard: the READ_PHONE_STATE request followed by a re-run of the SIM and
// call checks, the debug-only SIM baseline reset, the mitm pin (session
// restart with the pin in its config) and the reputation test list result.
// Fake: the native side and the permission answer — see
// test/support/fake_native.dart. Not exercised: the real permission dialog.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:rasp_trial/main.dart';
import 'package:rasp_trial/test_reputation_list.dart';

import 'support/fake_native.dart';

String _text(WidgetTester tester, String key) => tester.widget<Text>(find.byKey(Key(key))).data!;

Future<void> _settle(WidgetTester tester) async {
  for (var i = 0; i < 6; i++) {
    await tester.pump();
  }
}

void main() {
  testWidgets('Grant permissions asks for READ_PHONE_STATE, then re-runs and shows the SIM and call checks', (tester) async {
    final native = await bootTrialApp(tester);
    var asked = 0;
    requestPhonePermission = () async {
      asked++;
      return PermissionStatus.granted;
    };
    // On the refresh that follows the answer, the "engine" reports both checks.
    native.answer = (method, arguments) {
      if (method == 'refreshLeanSession') {
        final at = DateTime.now().millisecondsSinceEpoch + 1000;
        native.events.success(nativeState(detectors: {
          'sim_change': nativeCheck('sim_change', 'UNKNOWN', 'baseline stored', at),
          'vishing_call': nativeCheck('vishing_call', 'SECURE', null, at),
        }));
      }
      return true;
    };
    await emitState(tester, native, nativeState(detectors: {
      'sim_change': nativeCheck('sim_change', 'UNAVAILABLE', 'android.permission.READ_PHONE_STATE not granted to the host app'),
    }));

    await scrollTo(tester, find.byKey(const Key('grant-permissions')));
    expect(_text(tester, 'phone-permission'), 'Phone permission (READ_PHONE_STATE): not granted');
    final before = native.calls.length;
    await tester.tap(find.byKey(const Key('grant-permissions')));
    await _settle(tester);

    expect(asked, 1);
    expect(native.methods.sublist(before), contains('refreshLeanSession'));
    expect(_text(tester, 'phone-permission'), 'Phone permission (READ_PHONE_STATE): granted');
    final recheck = _text(tester, 'phone-recheck');
    expect(recheck, contains('SIM change: UNKNOWN (baseline stored)'));
    expect(recheck, contains('Call during app use: SECURE'));
  });

  testWidgets('Reset SIM baseline calls the native reset, then re-runs the checks', (tester) async {
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState());
    await scrollTo(tester, find.byKey(const Key('reset-sim-baseline')));
    final before = native.calls.length;
    await tester.tap(find.byKey(const Key('reset-sim-baseline')));
    await _settle(tester);

    expect(native.methods.sublist(before), containsAllInOrder(['resetSimBaseline', 'refreshLeanSession']));
    expect(find.textContaining('SIM baseline cleared'), findsOneWidget);
  });

  testWidgets('a refused reset (release build) is reported, not hidden', (tester) async {
    final native = await bootTrialApp(tester);
    native.answer = (method, arguments) => method == 'resetSimBaseline' ? false : true;
    await emitState(tester, native, nativeState());
    await scrollTo(tester, find.byKey(const Key('reset-sim-baseline')));
    await tester.tap(find.byKey(const Key('reset-sim-baseline')));
    await _settle(tester);
    expect(find.textContaining('SIM baseline not reset'), findsOneWidget);
  });

  testWidgets('Apply pin restarts the session with the pin in its config; No pin restarts it without', (tester) async {
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState());
    final first = native.argumentsOf('startLeanSession').single as Map;
    expect(first['certificatePinHost'], isNull);
    expect(first['certificatePins'], isEmpty);

    await scrollTo(tester, find.byKey(const Key('pin-host')));
    await tester.enterText(find.byKey(const Key('pin-host')), 'api.example.com');
    await scrollTo(tester, find.byKey(const Key('pin-value')));
    await tester.enterText(find.byKey(const Key('pin-value')), 'AAAA, sha256/BBBB');
    await scrollTo(tester, find.byKey(const Key('apply-pin')));
    await tester.tap(find.byKey(const Key('apply-pin')));
    await _settle(tester);

    final starts = native.argumentsOf('startLeanSession');
    expect(starts, hasLength(2));
    final pinned = starts.last as Map;
    expect(pinned['certificatePinHost'], 'api.example.com');
    expect(pinned['certificatePins'], ['sha256/AAAA', 'sha256/BBBB']);
    expect(native.methods, contains('disposeLeanSession'));
    expect(_text(tester, 'pin-status'), contains('api.example.com, 2 pin(s)'));

    await scrollTo(tester, find.byKey(const Key('clear-pin')));
    await tester.tap(find.byKey(const Key('clear-pin')));
    await _settle(tester);
    final cleared = native.argumentsOf('startLeanSession').last as Map;
    expect(native.argumentsOf('startLeanSession'), hasLength(3));
    expect(cleared['certificatePinHost'], isNull);
    expect(cleared['certificatePins'], isEmpty);
    expect(_text(tester, 'pin-status'), contains('none'));
  });

  testWidgets('the card shows the reputation result; the test-list switch restarts the session with the test list', (tester) async {
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState(detectors: {
      'malware_reputation': nativeCheck('malware_reputation', 'DETECTED'),
    }));
    await scrollTo(tester, find.byKey(const Key('reputation-result')));
    expect(_text(tester, 'reputation-result'), 'Result: DETECTED');
    expect(find.text('Malware reputation: use the test list (flags $testReputationPackage)'), findsOneWidget);
    expect(_text(tester, 'reputation-source'), startsWith('Off: the signed list from your backend'));
    final first = native.argumentsOf('startLeanSession').last as Map;
    expect(first['malwareReputationListJson'], isNull);

    await scrollTo(tester, find.byKey(const Key('test-reputation-list')));
    await tester.tap(find.byKey(const Key('test-reputation-list')));
    await _settle(tester);
    final restarted = native.argumentsOf('startLeanSession').last as Map;
    expect(restarted['malwareReputationListJson'], testReputationListJson);
    expect(restarted['malwareReputationAutoUpdate'], isFalse);
    expect(_text(tester, 'reputation-source'), startsWith('A harmless test entry'));
  });
}
