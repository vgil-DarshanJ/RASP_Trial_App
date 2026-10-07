// Backend Sync card: shows which backend the app sends to (host only) and
// lets the user replace a configured credential.
// Real: the dashboard, RaspSecurityEventShipper.restore/configure.
// Fake: the native side and secure storage (test/support/fake_native.dart),
// which returns a stored TEST credential (fake key and secret).
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';
import 'package:rasp_trial/backend_check.dart';

import 'support/fake_native.dart';

const _testSecret = 'test-secret-not-real';
const _storedCredential = '{"organization_id":"org_test","application_id":"app_test",'
    '"api_key":"key_test","api_secret":"$_testSecret",'
    '"ingestion_url":"http://192.168.2.208:4000/v1/events"}';

void main() {
  tearDown(RaspSecurityEventShipper.resetForTests);

  testWidgets('shows the backend host from the stored credential, never the key or secret', (tester) async {
    await bootTrialApp(tester, storedCredential: _storedCredential);
    await tester.pump();
    expect(tester.widget<Text>(find.byKey(const Key('backend-host'))).data, 'Sending to: 192.168.2.208:4000');
    expect(find.textContaining(_testSecret), findsNothing);
    expect(find.textContaining('key_test'), findsNothing);
  });

  testWidgets('Check connection asks the credential\'s backend and shows the answer', (tester) async {
    final checked = <String>[];
    final original = checkBackendConnection;
    checkBackendConnection = (origin) async {
      checked.add(origin);
      return describeBackendCheck(origin, error: 'SocketException');
    };
    addTearDown(() => checkBackendConnection = original);
    await bootTrialApp(tester, storedCredential: _storedCredential);
    await tester.pump();
    await tester.tap(find.byKey(const Key('check-connection')));
    await tester.pump();
    await tester.pump();
    expect(checked, ['http://192.168.2.208:4000']);
    final result = tester.widget<Text>(find.byKey(const Key('connection-result'))).data!;
    expect(result, startsWith('Cannot reach 192.168.2.208:4000'));
    expect(result, contains('paste a credential issued by your own dashboard'));
    expect(result.contains(_testSecret) || result.contains('key_test'), isFalse);
  });

  test('connection messages: reachable, backend problem, and the localhost / LAN hints', () {
    expect(describeBackendCheck('http://localhost:4000', status: 200), 'Reachable: localhost:4000 answered /healthz (HTTP 200).');
    expect(describeBackendCheck('http://10.0.0.5:4000', status: 503), contains('database or Redis is down'));
    final local = describeBackendCheck('http://localhost:4000', error: 'SocketException');
    expect(local, contains('"localhost" is the phone itself'));
    expect(local, contains('adb reverse tcp:4000 tcp:4000'));
    final lan = describeBackendCheck('http://192.168.2.208:4000', error: 'SocketException');
    expect(lan, contains('same network as 192.168.2.208:4000'));
    expect(lan, contains('port 4000'));
  });

  testWidgets('Change credential shows the paste field again', (tester) async {
    await bootTrialApp(tester, storedCredential: _storedCredential);
    await tester.pump();
    expect(find.text('Credential JSON'), findsNothing);
    await tester.tap(find.byKey(const Key('replace-credential')));
    await tester.pump();
    expect(find.text('Credential JSON'), findsOneWidget);
    expect(find.text('Cancel'), findsOneWidget);
  });
}
