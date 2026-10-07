// The "Fraud risk" trial screen (Task 8.1): simulate login, transaction and
// logout, show the verdict, switch high-risk transaction mode, show errors.
// Real: the dashboard, FraudRiskScreen, RaspLeanSession's calls and decoding.
// Fake: the native side (test/support/fake_native.dart). Its replies have the
// shape the Android handler sends; hashing and signing themselves are tested
// in the engine (RaspTask81Test).
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fake_native.dart';

const _medium = {
  'score': 40,
  'maxPossibleScore': 40,
  'verdict': 'MEDIUM',
  'stepUpRecommended': false,
  'firedGroups': ['device_compromise'],
  'undecidedGroups': <String>[],
  'contributingDetectors': ['root_jailbreak'],
  'highRiskTransactionMode': false,
  'evaluatedAtMillis': 1790000000000,
};

// Not const: a const map may not repeat the keys it overrides.
final _high = <String, Object?>{
  ..._medium,
  'score': 75,
  'maxPossibleScore': 75,
  'verdict': 'HIGH',
  'stepUpRecommended': true,
  'firedGroups': ['device_compromise', 'remote_access_overlay'],
};

Future<void> _openScreen(WidgetTester tester) async {
  await tester.tap(find.byTooltip('Fraud risk'));
  await tester.pumpAndSettle();
  expect(find.text('Fraud risk (trial)'), findsOneWidget);
}

/// The screen's own list (the text fields have scrollables of their own).
Finder get _list => find.descendant(of: find.byKey(const Key('fraud-list')), matching: find.byType(Scrollable)).first;

/// Scrolls the screen until [key] is built and visible (the list builds
/// lazily); a negative [delta] scrolls up, for the verdict at the top.
Future<Finder> _show(WidgetTester tester, String key, {double delta = 200}) async {
  final finder = find.byKey(Key(key));
  await tester.scrollUntilVisible(finder, delta, scrollable: _list);
  await tester.pump();
  return finder;
}

Future<void> _tap(WidgetTester tester, String key) async {
  await tester.tap(await _show(tester, key));
  await tester.pump();
  await tester.pump();
}

Future<String> _text(WidgetTester tester, String key, {double delta = 200}) async =>
    tester.widget<Text>(await _show(tester, key, delta: delta)).data!;

void main() {
  testWidgets('session risk scoring and the five fraud detectors are switched on', (tester) async {
    final native = await bootTrialApp(tester);
    final start = native.argumentsOf('startLeanSession').single as Map;
    expect(start['sessionRiskScoring'], isTrue);
    for (final flag in [
      'remoteControlAppDetection',
      'screenSharingDetection',
      'otpInterceptionDetection',
      'smsReaderAbuseDetection',
      'otpForwardingDetection',
    ]) {
      expect(start[flag], isTrue, reason: flag);
    }
  });

  testWidgets('Simulate login sends the demo ids to the native side and shows hashes and the verdict', (tester) async {
    final native = await bootTrialApp(tester);
    native.answer = (method, arguments) => method == 'reportLeanSession'
        ? {'accountHash': 'a' * 64, 'sessionHash': 'b' * 64, 'event': 'login', 'risk': _medium, 'sentToBackend': true}
        : null;
    await _openScreen(tester);
    await _tap(tester, 'fraud-login');

    final sent = native.argumentsOf('reportLeanSession').single as Map;
    expect(sent['accountId'], 'demo-account-1');
    expect(sent['event'], 'login');
    expect(sent['sessionId'] as String, startsWith('trial-'));
    expect(await _text(tester, 'fraud-result'), contains('Account hash aaaaaaaaaaaa…'));
    expect(await _text(tester, 'fraud-result'), contains('sent to the backend'));
    expect(await _text(tester, 'fraud-risk-verdict', delta: -200), 'Verdict MEDIUM · score 40');
  });

  testWidgets('Simulate transaction shows the binding and the step-up recommendation', (tester) async {
    final native = await bootTrialApp(tester);
    native.answer = (method, arguments) => method == 'reportLeanTransaction'
        ? {
            'transaction': {
              'canonical': 'rasp-txn-v1|1500|INR|${'c' * 64}|${'d' * 32}|1790000000000|9',
              'signature': 'MEUCIQ==',
              'counter': 9,
              'nonce': 'd' * 32,
              'timestampMillis': 1790000000000,
              'beneficiaryHash': 'c' * 64,
              'bindingSha256': 'e' * 64,
              'deviceKeyId': 'KEYID=',
              'risk': _high,
            },
            'channel': 'upi',
            'sentToBackend': false,
          }
        : null;
    await _openScreen(tester);
    await _tap(tester, 'fraud-transaction');

    expect(native.argumentsOf('reportLeanTransaction').single,
        {'amount': '1500.00', 'currency': 'INR', 'beneficiaryId': 'demo-beneficiary-1', 'channel': 'upi'});
    final result = await _text(tester, 'fraud-result');
    expect(result, contains('counter 9'));
    expect(result, contains('Binding eeeeeeeeeeee…'));
    expect(result, contains('not sent (no backend credential)'));
    expect(result, contains('step-up'));
    expect(await _text(tester, 'fraud-risk-verdict', delta: -200), 'Verdict HIGH · score 75 · step-up recommended');
  });

  testWidgets('a native error is shown, not a verdict', (tester) async {
    final native = await bootTrialApp(tester);
    native.answer = (method, arguments) => method == 'reportLeanTransaction'
        ? throw PlatformException(code: 'UNAVAILABLE', message: 'no active session: call reportSession(login) first')
        : null;
    await _openScreen(tester);
    await _tap(tester, 'fraud-transaction');
    expect(await _text(tester, 'fraud-error'), 'UNAVAILABLE: no active session: call reportSession(login) first');
    expect(find.byKey(const Key('fraud-result')), findsNothing);
  });

  testWidgets('the verdict follows the session state and the high-risk switch', (tester) async {
    final native = await bootTrialApp(tester);
    native.answer = (method, arguments) =>
        method == 'setLeanHighRiskTransactionMode' ? {..._medium, 'stepUpRecommended': true, 'highRiskTransactionMode': true} : null;
    await _openScreen(tester);
    expect(await _text(tester, 'fraud-risk-verdict', delta: -200), startsWith('Not computed yet'));

    await emitState(tester, native, {...nativeState(), 'risk': _medium});
    expect(await _text(tester, 'fraud-risk-verdict', delta: -200), 'Verdict MEDIUM · score 40');

    await _tap(tester, 'fraud-high-risk-mode');
    expect(native.argumentsOf('setLeanHighRiskTransactionMode').single, isTrue);
    expect(await _text(tester, 'fraud-risk-verdict', delta: -200), 'Verdict MEDIUM · score 40 · step-up recommended');
  });
}
