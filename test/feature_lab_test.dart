// Feature lab: the 43 features, their config flags, verdicts and log, and the
// list → feature page → Enable / Disable flow, driven through the real
// dashboard, the real lab screens and the real RaspLeanSession decoding.
// Fake: the native side — see test/support/fake_native.dart.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/core/core.dart' show DetectionStatus;
import 'package:rasp_shield/sdk/lean_session.dart' show RaspDetectorDescriptor, RaspLeanState;
import 'package:rasp_shield/sdk/security_controls.dart' show RaspClipboardEvidence, RaspUsbState;
import 'package:rasp_trial/detector_catalog.dart';
import 'package:rasp_trial/feature_catalog.dart';
import 'package:rasp_trial/feature_lab.dart';
import 'package:rasp_trial/feature_lab_screen.dart';
import 'package:rasp_trial/main.dart';

import 'support/fake_native.dart';

/// Native config key that switches each feature.
const _flagFor = <String, String>{
  'screenshot_protection': 'screenshotProtection', 'usb_connection': 'usbDetection',
  'adb_enabled': 'adbDetection', 'clipboard_protection': 'clipboardProtection',
  'root_jailbreak': 'rootDetection', 'emulator': 'emulatorDetection',
  'device_binding': 'deviceBindingCheck', 'clone': 'cloneDetection',
  'developer_mode': 'developerModeDetection', 'device_lock_missing': 'deviceLockCheck',
  'secure_hardware_unavailable': 'secureHardwareCheck', 'device_fingerprint': 'deviceFingerprintCheck',
  'device_state_attestation': 'deviceStateAttestationDetection', 'sim_change': 'simChangeDetection',
  'mock_location': 'mockLocationDetection', 'time_spoofing': 'timeSpoofingDetection',
  'malware_reputation': 'malwareReputationDetection',
  'frida': 'fridaDetection', 'debugger': 'debuggerDetection',
  're_tools': 'reverseEngineeringToolsDetection', 'hook_detection': 'hookDetection',
  'tamper': 'tamperDetection', 'repackage': 'repackagingDetection',
  'untrusted_install_source': 'untrustedInstallSourceDetection', 'task_hijack': 'taskHijackDetection',
  'vpn': 'vpnDetection', 'mitm': 'mitmDetection', 'high_risk_ip': 'highRiskIpDetection',
  'unsafe_wifi': 'unsafeWifiDetection', 'overlay': 'overlayDetection',
  'accessibility': 'accessibilityDetection', 'external_display': 'externalDisplayDetection',
  'screenshot_event': 'screenshotEventDetection', 'screen_recording': 'screenRecordingDetection',
  'vishing_call': 'vishingCallDetection', 'third_party_keyboard': 'thirdPartyKeyboardDetection',
  'remote_control_app': 'remoteControlAppDetection', 'screen_sharing_risk': 'screenSharingDetection',
  'otp_interception_risk': 'otpInterceptionDetection', 'sms_reader_abuse': 'smsReaderAbuseDetection',
  'otp_forwarding_risk': 'otpForwardingDetection', 'risky_app': 'riskyAppDetection',
  'remote_config_rejected': 'remoteConfigEnabled',
};

RaspLeanState _state({
  bool? usb,
  bool? adb,
  bool? screenshot,
  bool? clipboard,
  int copies = 0,
}) =>
    RaspLeanState(
      screenshotActive: screenshot,
      usb: RaspUsbState(
        supported: usb != null || adb != null,
        usbConnected: usb,
        usbDebuggingEnabled: adb,
        developerModeEnabled: null,
        connectedDeviceCount: usb == true ? 1 : 0,
      ),
      clipboardActive: clipboard,
      clipboardEvidence: RaspClipboardEvidence(
        supported: clipboard != null,
        active: clipboard ?? false,
        autoClearEnabled: true,
        changeCount: copies,
        lastChangeAt: null,
      ),
    );

void main() {
  group('catalog', () {
    test('43 features, no duplicates, exactly the engine\'s on-device detector ids', () {
      expect(trialFeatures, hasLength(43));
      expect(allFeatureIds.toSet(), hasLength(43));
      expect(allFeatureIds.toSet(), RaspDetectorDescriptor.knownIds.toSet());
      for (final f in trialFeatures) {
        expect(f.summary, isNotEmpty, reason: f.id);
        expect(f.howToShow, isNotEmpty, reason: f.id);
      }
    });

    test('the list order keeps the shared category headings and numbers 1..43', () {
      expect(featureDisplayOrder.toSet(), allFeatureIds.toSet());
      expect([for (final id in featureDisplayOrder) featureNumber(id)], [for (var i = 1; i <= 43; i++) i]);
      expect([for (final (heading, _) in groupByCategory(featureDisplayOrder)) heading],
          ['Device Integrity', 'Runtime Protection', 'App Integrity', 'Network Security', 'Privacy & Screen', 'Other']);
    });

    test('each feature switches exactly its own config flag', () {
      expect(_flagFor.keys.toSet(), allFeatureIds.toSet());
      final none = trialConfig(enabledFeatures: const {}).toNativeMap();
      for (final flag in _flagFor.values) {
        expect(none[flag], isFalse, reason: '$flag with nothing enabled');
      }
      for (final id in allFeatureIds) {
        final map = trialConfig(enabledFeatures: {id}).toNativeMap();
        for (final MapEntry(key: other, value: flag) in _flagFor.entries) {
          expect(map[flag], other == id, reason: 'only $id on: $flag');
        }
      }
    });

    test('the default is the trial config as before: repackage, screenshot_event and remote config off, the rest on', () {
      expect(trialConfig().toNativeMap(), trialConfig(enabledFeatures: defaultEnabledFeatureIds).toNativeMap());
      final map = trialConfig().toNativeMap();
      for (final MapEntry(key: id, value: flag) in _flagFor.entries) {
        expect(map[flag], !{'repackage', 'screenshot_event', 'remote_config_rejected'}.contains(id), reason: id);
      }
      expect(map['sessionRiskScoring'], isTrue, reason: 'not a feature: the Fraud risk screen needs it');
      expect(map['remoteManagedDetectors'], isEmpty, reason: 'a remote config never switches Feature lab choices');
    });
  });

  group('verdicts', () {
    test('basic controls: never SECURE from an unknown value', () {
      expect(featureVerdict(_state(), 'usb_connection').status, DetectionStatus.unknown);
      expect(featureVerdict(_state(), 'adb_enabled').status, DetectionStatus.unknown);
      expect(featureVerdict(_state(), 'screenshot_protection').status, isNull);
      expect(featureVerdict(_state(), 'clipboard_protection').status, isNull);
      expect(featureVerdict(_state(usb: true), 'usb_connection').status, DetectionStatus.detected);
      expect(featureVerdict(_state(adb: false), 'adb_enabled').status, DetectionStatus.secure);
      expect(featureVerdict(_state(screenshot: false), 'screenshot_protection').status, DetectionStatus.unavailable);
      expect(featureVerdict(_state(screenshot: true), 'screenshot_protection').status, DetectionStatus.secure);
      expect(featureVerdict(_state(), 'vpn').status, isNull, reason: 'no result yet');
    });

    test('the lab logs verdict changes once, switching off, and every clipboard copy', () async {
      final lab = FeatureLab(enabled: {'usb_connection', 'clipboard_protection'});
      lab.update(_state(usb: false, clipboard: true));
      lab.update(_state(usb: false, clipboard: true));
      lab.update(_state(usb: true, clipboard: true, copies: 1));
      expect([for (final e in lab.logFor('usb_connection')) e.status],
          [DetectionStatus.detected, DetectionStatus.secure]);
      expect(lab.logFor('clipboard_protection').first.status, DetectionStatus.detected);
      expect(lab.logFor('clipboard_protection').first.note, contains('Copy observed'));

      var restarts = 0;
      lab.onEnabledChanged = () async => restarts++;
      await lab.setEnabled('usb_connection', false);
      await lab.setEnabled('usb_connection', false);
      expect(restarts, 1, reason: 'no restart when nothing changes');
      expect(lab.logFor('usb_connection').first.status, isNull);
      expect(lab.logFor('usb_connection').first.note, 'Switched off');
      expect(lab.isEnabled('usb_connection'), isFalse);
    });
  });

  testWidgets('list of 43 → feature page → Disable / Enable restarts the session and the page shows the detection',
      (tester) async {
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState(detectors: {'vpn': nativeCheck('vpn', 'SECURE')}));

    expect(find.text('Feature lab (43)'), findsOneWidget);
    expect(find.text('40 enabled · 3 off'), findsOneWidget);

    final vpnTile = find.byKey(const Key('feature-tile-vpn'));
    await scrollTo(tester, vpnTile);
    expect(find.descendant(of: vpnTile, matching: find.text('Secure')), findsOneWidget);
    await tester.tap(vpnTile);
    await tester.pumpAndSettle();
    expect(find.text('Feature ${featureNumber('vpn')} of 43'), findsOneWidget);
    expect(find.text('Feature is ENABLED'), findsOneWidget);
    expect(find.text('No threat found'), findsOneWidget);

    // Disable: the session restarts without vpn.
    final startsBefore = native.argumentsOf('startLeanSession').length;
    await tester.tap(find.text('Disable'));
    await tester.pump();
    await tester.pump();
    final off = native.argumentsOf('startLeanSession');
    expect(off, hasLength(startsBefore + 1));
    expect((off.last as Map)['vpnDetection'], isFalse);
    expect((off.last as Map)['rootDetection'], isTrue, reason: 'the others stay on');
    await emitState(tester, native, nativeState());
    expect(find.text('Feature is DISABLED'), findsOneWidget);
    expect(find.text('Not running'), findsOneWidget);

    // Enable: restarts with vpn, and a DETECTED result is shown at once.
    await tester.tap(find.text('Enable'));
    await tester.pump();
    await tester.pump();
    expect((native.argumentsOf('startLeanSession').last as Map)['vpnDetection'], isTrue);
    await emitState(tester, native, nativeState(detectors: {'vpn': nativeCheck('vpn', 'DETECTED')}));
    expect(find.text('THREAT DETECTED'), findsOneWidget);
    await scrollTo(tester, find.text('Detection log'));
    expect(find.textContaining('Switched off'), findsOneWidget);

    // Next goes to the following feature in list order.
    await tester.tap(find.byKey(const Key('feature-next')));
    await tester.pumpAndSettle();
    expect(find.text('Feature ${featureNumber('vpn') + 1} of 43'), findsOneWidget);

    // Back on the list: the threat is counted.
    await tester.pageBack();
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(find.byKey(const Key('lab-threat-count')), -300,
        scrollable: find.byType(Scrollable).first);
    expect(find.text('1 threat detected'), findsOneWidget);
  });

  testWidgets('every one of the 43 tiles opens its own page', (tester) async {
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState());

    for (final id in featureDisplayOrder) {
      final tile = find.byKey(Key('feature-tile-$id'));
      await scrollTo(tester, tile);
      await tester.tap(tile);
      await tester.pumpAndSettle();
      expect(find.text('Feature ${featureNumber(id)} of 43'), findsOneWidget, reason: id);
      expect(find.text(featureById(id).title), findsWidgets, reason: id);
      expect(find.byKey(const Key('feature-enable-toggle')), findsOneWidget, reason: id);
      await tester.pageBack();
      await tester.pumpAndSettle();
    }
  });

  testWidgets('remote configuration: Enable turns remoteConfigEnabled on, the page shows status and version '
      'and checks for a new config', (tester) async {
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState());

    final tile = find.byKey(const Key('feature-tile-remote_config_rejected'));
    await scrollTo(tester, tile);
    expect(find.descendant(of: tile, matching: find.text('Off')), findsOneWidget);
    await tester.tap(tile);
    await tester.pumpAndSettle();
    expect(find.text('Remote Configuration Rejected'), findsWidgets);
    final status = find.byKey(const Key('feature-remote-config-status'));
    await scrollTo(tester, status);
    expect(find.text('Remote config: off'), findsOneWidget);

    await tester.scrollUntilVisible(find.text('Enable'), -300, scrollable: find.byType(Scrollable).first);
    await tester.tap(find.text('Enable'));
    await tester.pump();
    await tester.pump();
    final start = native.argumentsOf('startLeanSession').last as Map;
    expect(start['remoteConfigEnabled'], isTrue);
    expect(start['remoteManagedDetectors'], isEmpty);

    await emitState(tester, native, {
      ...nativeState(detectors: {'remote_config_rejected': nativeCheck('remote_config_rejected', 'SECURE')}),
      'remoteConfigStatus': 'APPLIED',
      'remoteConfigVersion': 3,
    });
    expect(find.text('No threat found'), findsOneWidget);
    await scrollTo(tester, status);
    expect(find.text('Remote config: applied'), findsOneWidget);
    expect(find.text('Applied version: 3'), findsOneWidget);

    final refresh = find.byKey(const Key('feature-remote-config-refresh'));
    await scrollTo(tester, refresh);
    await tester.tap(refresh);
    await tester.pump();
    expect(native.methods, contains('refreshLeanRemoteConfig'));

    await emitState(tester, native, {
      ...nativeState(detectors: {'remote_config_rejected': nativeCheck('remote_config_rejected', 'DETECTED')}),
      'remoteConfigStatus': 'REJECTED',
      'remoteConfigVersion': 3,
    });
    expect(find.textContaining('last config refused'), findsOneWidget);
    await tester.scrollUntilVisible(find.byKey(const Key('feature-headline')), -300,
        scrollable: find.byType(Scrollable).first);
    expect(find.text('THREAT DETECTED'), findsOneWidget);
  });
}
