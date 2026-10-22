import 'package:flutter/material.dart';
import 'package:rasp_shield/sdk/core/core.dart' show DetectionEvidence, DetectionStatus, DetectionStatusX;
import 'package:rasp_shield/sdk/lean_session.dart' show RaspDetectorDescriptor, RaspLeanState;

import 'detector_catalog.dart';

/// One of the 43 on-device features in the Feature lab: what it protects
/// against and how to show it working on a phone. Wording follows the
/// product rules: no absolute security claims, no other products' names.
class TrialFeature {
  final String id;
  final IconData icon;

  /// What the feature looks for, in one or two plain sentences.
  final String summary;

  /// Steps that make it report (or, for a protection, show) its result.
  final List<String> howToShow;

  /// What is needed first (permission, credential, Android version), if anything.
  final String? needs;

  /// `true` for the controls that protect rather than detect (screenshot
  /// block, clipboard): on = protected.
  final bool isProtection;

  const TrialFeature(
    this.id,
    this.icon, {
    required this.summary,
    required this.howToShow,
    this.needs,
    this.isProtection = false,
  });

  String get title => RaspDetectorDescriptor.forId(id).title;
}

/// The 43 features, numbered in this order on the Feature lab list: every
/// on-device detector id of the engine. `remote_config_rejected` is switched
/// by `remoteConfigEnabled` (the signed remote configuration).
const trialFeatures = <TrialFeature>[
  // ── The 4 basic controls ────────────────────────────────────────────
  TrialFeature('screenshot_protection', Icons.screenshot_monitor, isProtection: true,
      summary: 'Blocks screenshots and screen recording of this app (FLAG_SECURE). '
          'One control covers both still pictures and video.',
      howToShow: [
        'Enable the feature.',
        'Take a screenshot: Android refuses it, or the picture is black.',
        'Disable the feature and take one again: now the screen is captured.',
      ]),
  TrialFeature('usb_connection', Icons.usb,
      summary: 'Reports when a USB cable, computer or dock is connected to the phone.',
      howToShow: [
        'Enable the feature.',
        'Plug the phone into a computer with a USB cable: DETECTED within a few seconds.',
        'Unplug it: back to SECURE.',
      ]),
  TrialFeature('adb_enabled', Icons.developer_mode,
      summary: 'Reports when USB debugging (ADB) is switched on, which lets a computer control the phone.',
      howToShow: [
        'Enable the feature.',
        'Settings → Developer options → turn USB debugging on: DETECTED.',
        'Turn USB debugging off: SECURE.',
      ]),
  TrialFeature('clipboard_protection', Icons.content_paste_off, isProtection: true,
      summary: 'Notices when something is copied in this app and clears the clipboard, so '
          'account numbers or OTPs are not left behind for other apps. It never reads what was copied.',
      howToShow: [
        'Enable the feature.',
        'Type something in the test field below, select it and copy it.',
        'The copy shows in the detection log, and pasting elsewhere gives nothing.',
      ]),
  // ── Device integrity ────────────────────────────────────────────────
  TrialFeature('root_jailbreak', Icons.admin_panel_settings,
      summary: 'Looks for signs that the phone has been rooted, which removes Android\'s app isolation.',
      howToShow: [
        'Enable the feature.',
        'On a normal phone: SECURE.',
        'On a test phone prepared by your security team: DETECTED, with the signals listed as evidence.',
      ]),
  TrialFeature('emulator', Icons.devices_other,
      summary: 'Reports when the app runs on an emulator instead of a real phone — common in automated fraud.',
      howToShow: [
        'Enable the feature.',
        'On a real phone: SECURE.',
        'Install the same build on an Android emulator: DETECTED.',
      ]),
  TrialFeature('device_binding', Icons.link,
      summary: 'Keeps a hardware-backed key that ties this install to this phone, so a copied '
          'app data folder on another phone does not pass as the original.',
      howToShow: [
        'Enable the feature.',
        'First run: UNAVAILABLE "binding key was provisioned".',
        'Later runs on the same phone: SECURE.',
      ]),
  TrialFeature('clone', Icons.copy_all,
      summary: 'Reports when the app runs as a clone (dual-app or parallel space), where a second copy '
          'can be controlled by someone else.',
      howToShow: [
        'Enable the feature.',
        'Normal install: SECURE.',
        'Clone this app with the phone\'s own "dual apps" setting and open the clone: DETECTED.',
      ]),
  TrialFeature('developer_mode', Icons.code,
      summary: 'Reports when Developer options are unlocked on the phone.',
      howToShow: [
        'Enable the feature.',
        'Settings → About phone → tap Build number 7 times: DETECTED.',
        'Turn Developer options off: SECURE.',
      ]),
  TrialFeature('device_lock_missing', Icons.lock_open,
      summary: 'Reports when the phone has no screen lock (PIN, pattern, password or biometrics).',
      howToShow: [
        'Enable the feature.',
        'Settings → Security → Screen lock → None: DETECTED.',
        'Set a PIN again: SECURE.',
      ]),
  TrialFeature('secure_hardware_unavailable', Icons.memory,
      summary: 'Checks that the phone stores keys in secure hardware (TEE or StrongBox), not only in software.',
      howToShow: [
        'Enable the feature.',
        'Most current phones: SECURE.',
        'An emulator or very old phone: DETECTED.',
      ]),
  TrialFeature('device_fingerprint', Icons.fingerprint,
      summary: 'Sums up the phone\'s security posture (screen lock, USB debugging, SELinux, install source) '
          'and reports which parts are weak.',
      howToShow: [
        'Enable the feature.',
        'Turn USB debugging on, or remove the screen lock: DETECTED, with the reason in the evidence.',
        'Restore both: SECURE (a sideloaded test install still shows unknown_install_source).',
      ]),
  TrialFeature('device_state_attestation', Icons.verified,
      summary: 'Asks the phone\'s secure hardware to vouch for its boot state (locked bootloader, '
          'verified boot) and patch level.',
      howToShow: [
        'Enable the feature.',
        'Retail phone with a locked bootloader: SECURE.',
        'A phone with an unlocked bootloader: DETECTED.',
      ]),
  TrialFeature('sim_change', Icons.sim_card,
      needs: 'Phone permission (READ_PHONE_STATE).',
      summary: 'Remembers the SIM cards and reports when they change — a step in SIM-swap fraud.',
      howToShow: [
        'Enable the feature and grant the phone permission below.',
        'First check: UNKNOWN "baseline stored".',
        'Swap or remove a SIM and open the app: DETECTED.',
      ]),
  TrialFeature('mock_location', Icons.wrong_location,
      needs: 'Location permission and "Share location" on.',
      summary: 'Reports when the location comes from a mock-location app instead of the real GPS.',
      howToShow: [
        'Enable the feature and switch "Share location" on below.',
        'Real location: SECURE.',
        'Developer options → Select mock location app, start a fake location: DETECTED.',
      ]),
  TrialFeature('time_spoofing', Icons.schedule,
      summary: 'Reports when the phone\'s clock has been moved away from real time, which can defeat '
          'time-based limits and one-time codes.',
      howToShow: [
        'Enable the feature.',
        'Settings → Date & time → turn automatic time off, then move the clock by an hour.',
        'Come back to the app: DETECTED (two signals are needed, one alone is not enough).',
      ]),
  TrialFeature('malware_reputation', Icons.coronavirus_outlined,
      needs: 'A backend credential (signed list), or the test list from the Trial checks card.',
      summary: 'Compares installed apps with a signed list of known malicious apps.',
      howToShow: [
        'Enable the feature.',
        'On the main screen, Trial checks → switch "use the test list" on.',
        'The test list names a common app that is installed: DETECTED.',
      ]),
  // ── Runtime protection ──────────────────────────────────────────────
  TrialFeature('frida', Icons.bug_report,
      summary: 'Looks for a dynamic instrumentation toolkit attached to the app, used to change '
          'what the app does while it runs.',
      howToShow: [
        'Enable the feature.',
        'Normal use: SECURE.',
        'During an authorised penetration test of this build: DETECTED.',
      ]),
  TrialFeature('debugger', Icons.pest_control,
      summary: 'Reports a debugger attached to the app, or a debuggable build.',
      howToShow: [
        'Enable the feature.',
        'A debug build shows DETECTED (build_mode = debug) — expected in this trial build.',
        'A release build with no debugger: SECURE.',
      ]),
  TrialFeature('re_tools', Icons.build_circle_outlined,
      summary: 'Looks for reverse-engineering tools on the phone.',
      howToShow: [
        'Enable the feature.',
        'Normal phone: SECURE.',
        'A test phone with analysis tools installed by your security team: DETECTED.',
      ]),
  TrialFeature('hook_detection', Icons.phishing,
      summary: 'Looks for hooking frameworks that intercept the app\'s own method calls.',
      howToShow: [
        'Enable the feature.',
        'Normal phone: SECURE.',
        'A test phone prepared by your security team: DETECTED.',
      ]),
  // ── App integrity ───────────────────────────────────────────────────
  TrialFeature('tamper', Icons.healing,
      summary: 'Checks that the app\'s signing certificate is the one the build expects, so a modified '
          'copy is noticed.',
      howToShow: [
        'Enable the feature.',
        'This build: SECURE (the expected certificate is written into the build).',
        'A copy re-signed with another key: DETECTED.',
      ]),
  TrialFeature('repackage', Icons.inventory_2_outlined,
      summary: 'Reports when the app has been unpacked and rebuilt (repackaged) with another signature.',
      howToShow: [
        'Enable the feature.',
        'This build: SECURE.',
        'A rebuilt copy signed with another key: DETECTED.',
      ]),
  TrialFeature('untrusted_install_source', Icons.store_mall_directory_outlined,
      summary: 'Reports when the app was not installed from a trusted app store.',
      howToShow: [
        'Enable the feature.',
        'This trial build was installed from a computer or an APK file: DETECTED.',
        'The same app installed from the store: SECURE.',
      ]),
  TrialFeature('task_hijack', Icons.layers,
      summary: 'Reports another installed app that tries to join this app\'s task, so it can show a '
          'fake screen in the app\'s place.',
      howToShow: [
        'Enable the feature.',
        'Normal phone: SECURE.',
        'With a test app from your security team installed: DETECTED.',
      ]),
  TrialFeature('remote_config_rejected', Icons.settings_suggest,
      needs: 'A backend credential with a config public key (Backend Sync on the main screen).',
      summary: 'Fetches the app\'s signed settings from the backend and applies them only when the '
          'signature, app, expiry and version all check out. A refused config changes nothing and is '
          'reported here. In this trial it can change intervals and thresholds, never which features are on.',
      howToShow: [
        'Configure Backend Sync on the main screen, then enable the feature.',
        'Nothing published for this app yet: UNKNOWN "No remote config published for this app".',
        'An admin publishes a remote config for this app on the backend; tap "Check for a new config now": '
            'SECURE, with the version as evidence.',
        'The backend\'s config signing key is replaced while this phone keeps its old credential, and a '
            'new config is published: DETECTED (bad_signature). The last good config stays in use.',
      ]),
  // ── Network security ────────────────────────────────────────────────
  TrialFeature('vpn', Icons.vpn_key,
      summary: 'Reports when traffic goes through a VPN.',
      howToShow: [
        'Enable the feature.',
        'Connect any VPN app: DETECTED.',
        'Disconnect it: SECURE.',
      ]),
  TrialFeature('mitm', Icons.swap_horiz,
      summary: 'Reports a proxy, a user-installed certificate authority or a wrong server certificate — '
          'signs that someone can read the app\'s traffic.',
      howToShow: [
        'Enable the feature.',
        'Wi-Fi settings → this network → Proxy: Manual (any host): DETECTED.',
        'Set the proxy back to None: SECURE. For a pin check, set a pin in Trial checks.',
      ]),
  TrialFeature('high_risk_ip', Icons.public,
      needs: 'A backend credential (Backend Sync on the main screen).',
      summary: 'Asks the backend whether the phone\'s public IP address is high-risk (hosting, proxy, '
          'blocked country).',
      howToShow: [
        'Configure Backend Sync on the main screen, then enable the feature.',
        'Home or mobile network: SECURE.',
        'Through a data-centre VPN: DETECTED.',
      ]),
  TrialFeature('unsafe_wifi', Icons.wifi_off,
      summary: 'Reports an open (no password) or WEP Wi-Fi network, or one behind a login page.',
      howToShow: [
        'Enable the feature.',
        'Join an open guest network (or a phone hotspot with security "None"): DETECTED.',
        'Back on a WPA2/WPA3 network or mobile data: SECURE.',
      ]),
  // ── Privacy & screen ────────────────────────────────────────────────
  TrialFeature('overlay', Icons.picture_in_picture,
      summary: 'Reports when another app draws over this one while the user touches it — used to trick '
          'people into tapping the wrong thing.',
      howToShow: [
        'Enable the feature.',
        'Open a floating bubble or chat head from another app over this screen and tap through it: DETECTED.',
        'Close the bubble: SECURE after the next touch.',
      ]),
  TrialFeature('accessibility', Icons.accessibility_new,
      summary: 'Reports accessibility services that can read the screen or tap for the user, a common '
          'way for malware to take over a banking session.',
      howToShow: [
        'Enable the feature.',
        'Settings → Accessibility → turn on a downloaded accessibility app: DETECTED.',
        'Turn it off: SECURE.',
      ]),
  TrialFeature('external_display', Icons.cast,
      summary: 'Reports when the screen is mirrored or cast to another display.',
      howToShow: [
        'Enable the feature.',
        'Quick settings → Cast / Screen mirroring to a TV: DETECTED.',
        'Stop casting: SECURE.',
      ]),
  TrialFeature('screenshot_event', Icons.photo_camera,
      needs: 'Android 14 or newer.',
      summary: 'Reports the moment a screenshot of this app is taken.',
      howToShow: [
        'Enable the feature (and disable Screenshot & Video Block, so the screenshot is taken).',
        'Take a screenshot: DETECTED for one check, and it stays in the detection log.',
      ]),
  TrialFeature('screen_recording', Icons.videocam,
      needs: 'Android 15 or newer.',
      summary: 'Reports when this app\'s screen is being recorded.',
      howToShow: [
        'Enable the feature.',
        'Quick settings → Screen record → start: DETECTED.',
        'Stop recording: SECURE.',
      ]),
  TrialFeature('vishing_call', Icons.phone_in_talk,
      needs: 'Phone permission (READ_PHONE_STATE).',
      summary: 'Reports a phone call during app use — fraudsters often talk a victim through a transfer.',
      howToShow: [
        'Enable the feature and grant the phone permission below.',
        'Call this phone from another phone and answer, then return to the app: DETECTED.',
        'Hang up: SECURE.',
      ]),
  TrialFeature('third_party_keyboard', Icons.keyboard,
      summary: 'Reports when the active keyboard is not a system or trusted keyboard; a keyboard sees '
          'every password and OTP typed.',
      howToShow: [
        'Enable the feature.',
        'Install another keyboard app and make it the default keyboard: DETECTED.',
        'Switch back to the phone\'s own keyboard: SECURE.',
      ]),
  TrialFeature('remote_control_app', Icons.settings_remote,
      summary: 'Reports remote-support or remote-control apps installed, or screen sharing now — the tools '
          'used in remote-access scams.',
      howToShow: [
        'Enable the feature.',
        'Install a well-known remote-support app: DETECTED.',
        'Uninstall it: SECURE.',
      ]),
  TrialFeature('screen_sharing_risk', Icons.screen_share,
      needs: 'Android 15 or newer for recordings; casting works on any version.',
      summary: 'Reports when the screen is shared or cast while this app is open.',
      howToShow: [
        'Enable the feature.',
        'Start casting or a screen share, then open this app: DETECTED.',
        'Stop sharing: SECURE (UNKNOWN below Android 15 when nothing is cast).',
      ]),
  TrialFeature('otp_interception_risk', Icons.sms_failed,
      summary: 'Reports apps that can read notifications or the screen, so they could read an OTP.',
      howToShow: [
        'Enable the feature.',
        'Settings → Notification access → allow a downloaded app: DETECTED.',
        'Remove the access: SECURE.',
      ]),
  TrialFeature('sms_reader_abuse', Icons.mark_email_unread,
      summary: 'Lists apps (other than the default SMS app) that are allowed to read SMS. It never reads '
          'any message.',
      howToShow: [
        'Enable the feature.',
        'Grant the SMS permission to a downloaded app: DETECTED.',
        'Remove the permission: SECURE, or UNKNOWN where Android limits which apps are visible.',
      ]),
  TrialFeature('otp_forwarding_risk', Icons.forward_to_inbox,
      summary: 'A risk hint: SMS auto-forward apps, accessibility services that can tap, or remote-control '
          'apps that could pass an OTP on. Never proof that an OTP was forwarded.',
      howToShow: [
        'Enable the feature.',
        'Install an SMS auto-forward app, or turn on an accessibility app: DETECTED (risk hint).',
        'Remove it: SECURE.',
      ]),
  // ── Other ───────────────────────────────────────────────────────────
  TrialFeature('risky_app', Icons.warning_amber_rounded,
      summary: 'Looks for apps and settings on the phone that make fraud easier (for example tools that '
          'change the device identity).',
      howToShow: [
        'Enable the feature.',
        'Normal phone: SECURE.',
        'A test phone set up by your security team: DETECTED, with the app category as evidence.',
      ]),
];

TrialFeature featureById(String id) => trialFeatures.firstWhere((f) => f.id == id);

/// Ids of every feature, in list order.
final allFeatureIds = <String>[for (final f in trialFeatures) f.id];

/// On when the app starts: everything the trial app has always enabled
/// (the 4 basic controls and [trialDetectorIds]); `repackage`,
/// `screenshot_event` and `remote_config_rejected` (remote configuration is
/// off by default in the SDK too) start off and can be switched on in the
/// Feature lab.
final defaultEnabledFeatureIds = <String>{
  'screenshot_protection', 'usb_connection', 'adb_enabled', 'clipboard_protection',
  ...trialDetectorIds,
};

/// A feature's current verdict on the phone.
class FeatureVerdict {
  /// `null` while the feature is enabled but no result has arrived yet.
  final DetectionStatus? status;
  final String? reason;
  final List<DetectionEvidence> evidence;

  const FeatureVerdict(this.status, {this.reason, this.evidence = const []});

  bool get isThreat => status?.isThreat ?? false;
}

/// The verdict for [id] from the session state. The 4 basic controls come
/// from their own state fields, with the same verdicts the engine ships
/// (`leanControlResults`); `null` from the SDK is never shown as SECURE.
FeatureVerdict featureVerdict(RaspLeanState state, String id) {
  switch (id) {
    case 'screenshot_protection':
      final active = state.screenshotActive;
      if (active == null) return const FeatureVerdict(null);
      return active
          ? const FeatureVerdict(DetectionStatus.secure, reason: 'Screenshots and recording are blocked')
          : const FeatureVerdict(DetectionStatus.unavailable, reason: 'Screenshots are not blocked');
    case 'usb_connection':
      return _boolVerdict(state.usb.usbConnected, 'USB state could not be read',
          [DetectionEvidence(key: 'device_count', value: state.usb.connectedDeviceCount)]);
    case 'adb_enabled':
      return _boolVerdict(state.usb.usbDebuggingEnabled, 'ADB setting could not be read', const []);
    case 'clipboard_protection':
      final active = state.clipboardActive;
      if (active == null) return const FeatureVerdict(null);
      final evidence = [DetectionEvidence(key: 'change_count', value: state.clipboardEvidence.changeCount)];
      return active
          ? FeatureVerdict(DetectionStatus.secure, reason: 'Guarding the clipboard', evidence: evidence)
          : FeatureVerdict(DetectionStatus.unavailable, reason: 'Clipboard is not guarded', evidence: evidence);
  }
  final result = state.extendedDetectors[id];
  if (result == null) return const FeatureVerdict(null);
  return FeatureVerdict(result.status, reason: result.unavailableReason, evidence: result.evidence);
}

FeatureVerdict _boolVerdict(bool? detected, String unknownReason, List<DetectionEvidence> evidence) =>
    switch (detected) {
      true => FeatureVerdict(DetectionStatus.detected, evidence: evidence),
      false => FeatureVerdict(DetectionStatus.secure, evidence: evidence),
      null => FeatureVerdict(DetectionStatus.unknown, reason: unknownReason),
    };

/// A clipboard copy observed in this state (the count is per check).
bool clipboardCopySeen(RaspLeanState state) =>
    state.clipboardActive == true && state.clipboardEvidence.changeCount > 0;
