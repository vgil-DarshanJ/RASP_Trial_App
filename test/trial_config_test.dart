// The trial app's detector configuration (Task 4.6): every new detector and
// envelope mode are on, and every id the results screen lists is enabled.
// Real: trialConfig.toNativeMap() (the map sent to the native plugin) and
// trialDetectorIds. No platform channel involved.
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_trial/detector_results_screen.dart';
import 'package:rasp_trial/main.dart';

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
  final map = trialConfig.toNativeMap();

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
