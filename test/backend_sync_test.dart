// Backend Sync card: shows which backend the app sends to (host only) and
// lets the user replace a configured credential.
// Real: the dashboard, RaspSecurityEventShipper.restore/configure.
// Fake: the native side and secure storage (test/support/fake_native.dart),
// which returns a stored TEST credential (fake key and secret).
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';

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
