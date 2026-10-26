// Task 6.0, trial app side: the opt-in "Share location" switch (and, Task 9.3,
// the last location heartbeat result) and the
// build-time signing certificate hash.
// Real: TrialBuildConfig, trialConfig().toNativeMap(), the dashboard and the
// plugin's RaspLeanSession. Fake: the native side (test/support/fake_native.dart),
// the permission answer and the location fix. Not exercised: the Gradle task
// that writes assets/generated/rasp_build.json (checked by building the APK)
// and a real GPS fix.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLocationSnapshot;
import 'package:rasp_trial/build_config.dart';
import 'package:rasp_trial/main.dart';

import 'support/fake_native.dart';

class _Bundle extends CachingAssetBundle {
  _Bundle(this.text);
  final String? text;
  @override
  Future<ByteData> load(String key) async {
    if (text == null) throw FlutterError('missing $key');
    return ByteData.sublistView(Uint8List.fromList(text!.codeUnits));
  }
}

final _hash = 'A1' * 32;

void main() {
  group('build config', () {
    test('reads the signing certificate hash the Android build wrote', () async {
      final config = await TrialBuildConfig.load(
        _Bundle('{"variant":"debug","signingConfig":"debug","expectedSigningCertSha256":"$_hash"}'),
      );
      expect(config.expectedSigningCertSha256, _hash);
      expect(config.variant, 'debug');
    });

    test('missing file or a malformed hash means nothing configured', () async {
      expect((await TrialBuildConfig.load(_Bundle(null))).expectedSigningCertSha256, isNull);
      expect(TrialBuildConfig.parse('{"expectedSigningCertSha256":"not-a-hash"}').expectedSigningCertSha256, isNull);
      expect(TrialBuildConfig.parse('{"expectedSigningCertSha256":null}').expectedSigningCertSha256, isNull);
    });

    test('the hash reaches the SDK config for tamper', () {
      expect(trialConfig(expectedSigningCertSha256: _hash).toNativeMap()['expectedSigningCertSha256'], _hash);
      expect(trialConfig().toNativeMap()['expectedSigningCertSha256'], isNull);
    });
  });

  group('Share location', () {
    late int permissionRequests;
    late int fixReads;
    late PermissionStatus answer;

    void fakeLocation() {
      permissionRequests = 0;
      fixReads = 0;
      answer = PermissionStatus.granted;
      final originalRequest = requestLocationPermission;
      final originalRead = readLocationFix;
      requestLocationPermission = () async {
        permissionRequests++;
        return answer;
      };
      readLocationFix = () async {
        fixReads++;
        return RaspLocationSnapshot(
          latitude: 28.61394, longitude: 77.20902, accuracyMeters: 12,
          capturedAt: DateTime.now().toUtc(), isMock: false, shareWithBackend: true,
        );
      };
      addTearDown(() {
        requestLocationPermission = originalRequest;
        readLocationFix = originalRead;
      });
    }

    testWidgets('is off by default and no location is read or sent before opt-in', (tester) async {
      fakeLocation();
      final native = await bootTrialApp(tester);
      await emitState(tester, native, nativeState());
      await tester.pump(const Duration(seconds: 20));
      await openFeature(tester, 'mock_location');
      await scrollTo(tester, find.byKey(const Key('share-location')));
      expect(tester.widget<SwitchListTile>(find.byKey(const Key('share-location'))).value, isFalse);
      expect(permissionRequests, 0);
      expect(fixReads, 0);
      expect(native.methods, isNot(contains('setLeanSessionLocation')));
    });

    testWidgets('turning it on asks for location and sends opted-in fixes; off clears them', (tester) async {
      fakeLocation();
      final native = await bootTrialApp(tester);
      await emitState(tester, native, nativeState());
      await openFeature(tester, 'mock_location');
      await scrollTo(tester, find.byKey(const Key('share-location')));
      await tester.tap(find.byKey(const Key('share-location')));
      for (var i = 0; i < 6; i++) {
        await tester.pump();
      }
      expect(permissionRequests, 1);
      final sent = native.argumentsOf('setLeanSessionLocation').cast<Map>();
      expect(sent, isNotEmpty);
      expect(sent.last['shareWithBackend'], isTrue);
      expect(sent.last['isMock'], isFalse);
      expect(tester.widget<Text>(find.byKey(const Key('last-fix'))).data, contains('28.614, 77.209'));

      await tester.pump(const Duration(seconds: 15));
      await tester.pump();
      expect(fixReads, 2, reason: 'a new fix every 15 s while on');

      await tester.tap(find.byKey(const Key('share-location')));
      for (var i = 0; i < 4; i++) {
        await tester.pump();
      }
      expect(native.methods, contains('clearLeanSessionLocation'));
      await tester.pump(const Duration(seconds: 30));
      expect(fixReads, 2, reason: 'no more reads after turning it off');
    });

    testWidgets('the card shows the delivery result of the last location heartbeat (Task 9.3)', (tester) async {
      fakeLocation();
      final native = await bootTrialApp(tester);
      await emitState(tester, native, nativeState());
      await openFeature(tester, 'mock_location');
      await scrollTo(tester, find.byKey(const Key('location-heartbeat')));
      String label() => tester.widget<Text>(find.byKey(const Key('location-heartbeat'))).data!;
      expect(label(), 'Location heartbeat: off.');

      await scrollTo(tester, find.byKey(const Key('share-location')));
      await tester.tap(find.byKey(const Key('share-location')));
      for (var i = 0; i < 6; i++) {
        await tester.pump();
      }
      expect(label(), startsWith('Location heartbeat: not sent yet'));

      final at = DateTime(2026, 10, 7, 12, 0, 5).millisecondsSinceEpoch;
      await emitState(tester, native, {
        ...nativeState(),
        'locationHeartbeat': {'atMillis': at, 'outcome': 'DELIVERED', 'detail': 'delivered', 'cleared': false},
      });
      expect(label(), 'Location heartbeat at 12:00:05: delivered');

      await emitState(tester, native, {
        ...nativeState(),
        'locationHeartbeat': {'atMillis': at + 60000, 'outcome': 'REJECTED', 'detail': 'HTTP 401', 'cleared': false},
      });
      expect(label(), 'Location heartbeat at 12:01:05: rejected: HTTP 401');

      await scrollTo(tester, find.byKey(const Key('share-location')));
      await tester.tap(find.byKey(const Key('share-location')));
      for (var i = 0; i < 4; i++) {
        await tester.pump();
      }
      await emitState(tester, native, {
        ...nativeState(),
        'locationHeartbeat': {'atMillis': at + 90000, 'outcome': 'DELIVERED', 'detail': 'delivered', 'cleared': true},
      });
      expect(label(), 'Sharing-off message at 12:01:35: delivered (backend location cleared)');
      expect(find.byKey(const Key('last-fix')), findsNothing, reason: 'the fix is cleared on the phone too');
    });

    testWidgets('a refused permission keeps it off and sends nothing', (tester) async {
      fakeLocation();
      answer = PermissionStatus.denied;
      final native = await bootTrialApp(tester);
      await emitState(tester, native, nativeState());
      await openFeature(tester, 'mock_location');
      await scrollTo(tester, find.byKey(const Key('share-location')));
      await tester.tap(find.byKey(const Key('share-location')));
      for (var i = 0; i < 4; i++) {
        await tester.pump();
      }
      expect(tester.widget<SwitchListTile>(find.byKey(const Key('share-location'))).value, isFalse);
      expect(fixReads, 0);
      expect(native.methods, isNot(contains('setLeanSessionLocation')));
      expect(find.textContaining('Location permission not granted'), findsOneWidget);
    });
  });
}
