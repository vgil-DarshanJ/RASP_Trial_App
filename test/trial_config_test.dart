// The trial app's detector configuration (Tasks 4.6, 4.8): every new detector
// and envelope mode are on, every id the results screen lists is enabled, the
// signed test reputation list is configured, and the mitm pin is off unless set.
// Real: trialConfig().toNativeMap() (the map sent to the native plugin),
// trialDetectorIds and lib/test_reputation_list.dart. No platform channel.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_trial/detector_catalog.dart';
import 'package:rasp_trial/main.dart';
import 'package:rasp_trial/test_reputation_list.dart';

/// Native config key that enables each detector id.
const _flagFor = <String, String>{
  'root_jailbreak': 'rootDetection', 'emulator': 'emulatorDetection',
  'device_binding': 'deviceBindingCheck', 'clone': 'cloneDetection',
  'developer_mode': 'developerModeDetection', 'device_lock_missing': 'deviceLockCheck',
  'secure_hardware_unavailable': 'secureHardwareCheck', 'device_fingerprint': 'deviceFingerprintCheck',
  'device_state_attestation': 'deviceStateAttestationDetection', 'sim_change': 'simChangeDetection',
  'mock_location': 'mockLocationDetection', 'time_spoofing': 'timeSpoofingDetection',
  'frida': 'fridaDetection', 'debugger': 'debuggerDetection',
  're_tools': 'reverseEngineeringToolsDetection', 'hook_detection': 'hookDetection',
  'risky_app': 'riskyAppDetection', 'malware_reputation': 'malwareReputationDetection',
  'tamper': 'tamperDetection', 'untrusted_install_source': 'untrustedInstallSourceDetection',
  'task_hijack': 'taskHijackDetection', 'vpn': 'vpnDetection', 'mitm': 'mitmDetection',
  'high_risk_ip': 'highRiskIpDetection', 'unsafe_wifi': 'unsafeWifiDetection',
  'overlay': 'overlayDetection', 'accessibility': 'accessibilityDetection',
  'external_display': 'externalDisplayDetection', 'screen_recording': 'screenRecordingDetection',
  'vishing_call': 'vishingCallDetection', 'third_party_keyboard': 'thirdPartyKeyboardDetection',
};

void main() {
  final map = trialConfig().toNativeMap();

  test('envelope mode is on', () {
    expect(map['useEvidenceEnvelope'], isTrue);
  });

  test('every detector the results screen lists is enabled in the config', () {
    expect(trialDetectorIds.toSet().length, trialDetectorIds.length, reason: 'no duplicates');
    for (final id in trialDetectorIds) {
      final flag = _flagFor[id];
      expect(flag, isNotNull, reason: 'no config flag known for $id');
      expect(map[flag], isTrue, reason: '$id ($flag) should be enabled');
    }
  });

  test('malware_reputation gets the signed test list, which names the test package', () {
    expect(map['malwareReputationListJson'], testReputationListJson);
    expect(map['malwareReputationPublicKey'], testReputationPublicKey);
    final outer = jsonDecode(testReputationListJson) as Map<String, dynamic>;
    final payload = jsonDecode(outer['payload'] as String) as Map<String, dynamic>;
    expect([for (final e in payload['entries'] as List) e['package']], [testReputationPackage]);
    expect(base64Decode(outer['signature'] as String), hasLength(64), reason: 'Ed25519 signature');
    expect(base64Decode(testReputationPublicKey), hasLength(44), reason: 'X.509 SPKI of an Ed25519 key');
  });

  test('mitm pin: none by default, set through trialConfig(pinHost:, pins:)', () {
    expect(map['certificatePinHost'], isNull);
    expect(map['certificatePins'], isEmpty);
    final pinned = trialConfig(pinHost: 'api.example.com', pins: ['sha256/AAAA']).toNativeMap();
    expect(pinned['certificatePinHost'], 'api.example.com');
    expect(pinned['certificatePins'], ['sha256/AAAA']);
  });

  test('all ten detectors from Tasks 3a-3c are enabled', () {
    for (final flag in const [
      'mockLocationDetection', 'timeSpoofingDetection', 'unsafeWifiDetection', 'screenRecordingDetection',
      'vishingCallDetection', 'simChangeDetection', 'thirdPartyKeyboardDetection', 'taskHijackDetection',
      'deviceStateAttestationDetection', 'malwareReputationDetection',
    ]) {
      expect(map[flag], isTrue, reason: flag);
    }
  });
}
