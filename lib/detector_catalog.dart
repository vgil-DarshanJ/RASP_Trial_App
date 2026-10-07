import 'package:rasp_shield/sdk/core/core.dart' show ThreatCategory;
import 'package:rasp_shield/sdk/lean_session.dart' show RaspDetectorDescriptor, RaspThreatCategoryHeading;

/// Detector ids this trial app turns on (see `trialConfig` in main.dart).
const trialDetectorIds = <String>[
  'root_jailbreak', 'emulator', 'device_binding', 'clone', 'developer_mode',
  'device_lock_missing', 'secure_hardware_unavailable', 'device_fingerprint',
  'device_state_attestation', 'sim_change', 'mock_location', 'time_spoofing',
  'malware_reputation',
  'frida', 'debugger', 're_tools', 'hook_detection',
  'tamper', 'untrusted_install_source', 'task_hijack',
  'vpn', 'mitm', 'high_risk_ip', 'unsafe_wifi',
  'overlay', 'accessibility', 'external_display', 'screen_recording',
  'vishing_call', 'third_party_keyboard',
  'remote_control_app', 'screen_sharing_risk', 'otp_interception_risk',
  'sms_reader_abuse', 'otp_forwarding_risk',
  'risky_app',
];

/// Order of category headings on both screens.
const categoryOrder = <ThreatCategory>[
  ThreatCategory.deviceIntegrity,
  ThreatCategory.runtimeProtection,
  ThreatCategory.appIntegrity,
  ThreatCategory.networkSecurity,
  ThreatCategory.privacyScreen,
  ThreatCategory.locationIntegrity,
  ThreatCategory.other,
];

/// Display name for a detector id (the plugin's descriptor title).
String detectorName(String id) => RaspDetectorDescriptor.forId(id).title;

/// The ids both screens show: every enabled detector, then any other id
/// that has reported a result.
List<String> displayedDetectorIds(Iterable<String> reportedIds) => [
      ...trialDetectorIds,
      ...(reportedIds.where((id) => !trialDetectorIds.contains(id)).toList()..sort()),
    ];

/// The main screen's subset of [displayedDetectorIds]: only ids that have
/// reported a result, in the same order.
List<String> reportedDetectorIds(Iterable<String> reportedIds) {
  final reported = reportedIds.toSet();
  return displayedDetectorIds(reported).where(reported.contains).toList();
}

/// [ids] grouped under their category heading, in [categoryOrder]; inside a
/// group the order of [ids] is kept. Used by the main screen and the
/// results screen so both show the same headings, names and order.
List<(String heading, List<String> ids)> groupByCategory(List<String> ids) {
  final groups = <ThreatCategory, List<String>>{};
  for (final id in ids) {
    groups.putIfAbsent(RaspDetectorDescriptor.forId(id).category, () => []).add(id);
  }
  return [
    for (final category in categoryOrder)
      if (groups[category] != null) (category.heading, groups[category]!),
  ];
}
