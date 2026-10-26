// First-launch permission explanation (Task 9.2): shown once, Phone state
// asked first (on Continue), Location only when Share location is switched
// on, refused answers explained with an Open Settings button.
// Real: the dashboard, PermissionIntroDialog, showPermissionRefusedDialog,
// the default SharedPreferences store (with the plugin's in-memory mock).
// Fake: the native side (test/support/fake_native.dart), the permission
// requests (permission_handler), the stored answer for the app tests, and
// opening system settings (counted).
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:rasp_trial/main.dart';
import 'package:rasp_trial/permission_onboarding.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support/fake_native.dart';

/// Lets an async chain (dialog result → store → request) run to the next frame.
Future<void> settle(WidgetTester tester) async {
  for (var i = 0; i < 6; i++) {
    await tester.pump();
  }
}

void main() {
  late List<String> requests;
  late PermissionStatus phoneAnswer;
  late PermissionStatus locationAnswer;

  setUp(() {
    requests = [];
    phoneAnswer = PermissionStatus.granted;
    locationAnswer = PermissionStatus.granted;
  });

  /// Boots the app and replaces both permission requests (after boot, which
  /// installs its own phone request).
  /// [introAnswer] `null` = first launch (explanation shown).
  Future<FakeNative> boot(WidgetTester tester, {String? introAnswer = 'continue'}) async {
    final native = await bootTrialApp(tester, introAnswer: introAnswer);
    requestPhonePermission = () async {
      requests.add('phone');
      return phoneAnswer;
    };
    final originalLocation = requestLocationPermission;
    requestLocationPermission = () async {
      requests.add('location');
      return locationAnswer;
    };
    addTearDown(() => requestLocationPermission = originalLocation);
    await settle(tester);
    return native;
  }

  testWidgets('first launch: the explanation names both permissions and says location is optional', (tester) async {
    await boot(tester, introAnswer: null);
    expect(find.byKey(const Key('permission-intro')), findsOneWidget);
    expect(find.text('Phone state'), findsOneWidget);
    expect(find.text('Location (optional)'), findsOneWidget);
    expect(find.textContaining('Off until you switch on Share location'), findsOneWidget);
    expect(requests, isEmpty, reason: 'nothing is asked before the explanation is answered');
  });

  testWidgets('Continue asks for Phone state only, and the answer is remembered', (tester) async {
    final native = await boot(tester, introAnswer: null);
    await tester.tap(find.byKey(const Key('permission-intro-continue')));
    await settle(tester);
    expect(requests, ['phone'], reason: 'location is not asked here');
    expect(native.savedIntroAnswers, ['continue']);
    expect(find.byKey(const Key('permission-intro')), findsNothing);
    expect(find.byKey(const Key('permission-refused')), findsNothing, reason: 'granted: nothing to explain');
    await tester.pump(const Duration(seconds: 16)); // the SIM re-check's wait times out
  });

  testWidgets('Not now asks for nothing and is remembered too', (tester) async {
    final native = await boot(tester, introAnswer: null);
    await tester.tap(find.byKey(const Key('permission-intro-not-now')));
    await settle(tester);
    expect(requests, isEmpty);
    expect(native.savedIntroAnswers, ['not_now']);
    expect(find.byKey(const Key('permission-intro')), findsNothing);
  });

  testWidgets('an answered explanation is not shown again', (tester) async {
    await boot(tester, introAnswer: 'not_now');
    expect(find.byKey(const Key('permission-intro')), findsNothing);
    expect(requests, isEmpty);
  });

  testWidgets('Phone state denied: explained, with Open Settings', (tester) async {
    phoneAnswer = PermissionStatus.denied;
    final native = await boot(tester, introAnswer: null);
    await tester.tap(find.byKey(const Key('permission-intro-continue')));
    await settle(tester);
    expect(find.text('Phone state not granted'), findsOneWidget);
    expect(find.textContaining('SIM change and Call during app use stay UNAVAILABLE'), findsOneWidget);
    await tester.tap(find.byKey(const Key('permission-open-settings')));
    await settle(tester);
    expect(native.settingsOpened, 1);
    expect(find.byKey(const Key('permission-refused')), findsNothing);
    await tester.pump(const Duration(seconds: 16));
  });

  testWidgets('Phone state permanently denied: "blocked", Open Settings or Close', (tester) async {
    phoneAnswer = PermissionStatus.permanentlyDenied;
    final native = await boot(tester, introAnswer: null);
    await tester.tap(find.byKey(const Key('permission-intro-continue')));
    await settle(tester);
    expect(find.text('Phone state is blocked'), findsOneWidget);
    expect(find.textContaining('Android will not ask again'), findsOneWidget);
    await tester.tap(find.byKey(const Key('permission-refused-close')));
    await settle(tester);
    expect(native.settingsOpened, 0);
    expect(find.byKey(const Key('permission-refused')), findsNothing);
    await tester.pump(const Duration(seconds: 16));
  });

  testWidgets('Location is asked only when Share location is switched on; blocked → Open Settings, switch stays off',
      (tester) async {
    locationAnswer = PermissionStatus.permanentlyDenied;
    final native = await boot(tester);
    expect(requests, isEmpty);
    await emitState(tester, native, nativeState());
    await openFeature(tester, 'mock_location');
    await scrollTo(tester, find.byKey(const Key('share-location')));
    await tester.tap(find.byKey(const Key('share-location')));
    await settle(tester);
    expect(requests, ['location']);
    expect(find.text('Location is blocked'), findsOneWidget);
    expect(find.textContaining('Location permission not granted'), findsOneWidget);
    await tester.tap(find.byKey(const Key('permission-open-settings')));
    await settle(tester);
    expect(native.settingsOpened, 1);
    expect(tester.widget<SwitchListTile>(find.byKey(const Key('share-location'))).value, isFalse);
  });

  test('the default store keeps the answer across reads (SharedPreferences)', () async {
    SharedPreferences.setMockInitialValues({});
    expect(await readPermissionIntroAnswer(), isNull);
    await savePermissionIntroAnswer('continue');
    expect(await readPermissionIntroAnswer(), 'continue');
    expect((await SharedPreferences.getInstance()).getString(permissionIntroKey), 'continue');
  });

  test('refused means denied, permanently denied or restricted', () {
    expect(isRefused(PermissionStatus.denied), isTrue);
    expect(isRefused(PermissionStatus.permanentlyDenied), isTrue);
    expect(isRefused(PermissionStatus.restricted), isTrue);
    expect(isRefused(PermissionStatus.granted), isFalse);
    expect(isRefused(PermissionStatus.limited), isFalse);
  });
}
