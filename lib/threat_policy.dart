import 'package:rasp_shield/sdk/core/core.dart' show DetectionResult, DetectionStatus;
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLeanState;

/// Device-posture warnings for the banner at the top of the main screen.
/// Developer options, USB debugging, a USB connection and an unsafe Wi-Fi
/// network are warned about — the app keeps running.
List<String> postureWarnings(RaspLeanState state) => [
      if (state.usb.developerModeEnabled == true) 'Developer options are unlocked on this device.',
      if (state.usb.usbDebuggingEnabled == true) 'USB debugging (ADB) is enabled.',
      if (state.usb.usbConnected == true) 'A USB cable or dock is connected.',
      ?unsafeWifiWarning(state),
    ];

/// Plain wording for `unsafe_wifi`'s `wifi_signal` evidence.
const _wifiSignalWords = {
  'open_network': 'it has no password, so people nearby can read the traffic',
  'wep_network': 'it uses old WEP encryption that is easy to break',
  'captive_portal': 'it asks for a sign-in page (captive portal)',
};

/// The banner line while `unsafe_wifi` is DETECTED, else `null`.
String? unsafeWifiWarning(RaspLeanState state) {
  final result = state.extendedDetectors['unsafe_wifi'];
  if (result?.status != DetectionStatus.detected) return null;
  final why = result!.evidence
      .where((e) => e.key == 'wifi_signal')
      .map((e) => _wifiSignalWords[e.value] ?? '${e.value}')
      .join('; ');
  return why.isEmpty ? 'Unsafe Wi-Fi network.' : 'Unsafe Wi-Fi network: $why.';
}

/// A pop-up for a Wi-Fi change between two readings, or `null`:
/// - `unsafe_wifi` just became DETECTED (also at the first reading) → an
///   unsafe alert;
/// - the phone just joined a Wi-Fi network that is not unsafe → a notice
///   with its security type.
({String message, bool unsafe})? wifiChangeAlert(RaspLeanState? previous, RaspLeanState current) {
  final now = current.extendedDetectors['unsafe_wifi'];
  if (now == null) return null;
  final before = previous?.extendedDetectors['unsafe_wifi'];
  if (now.status == DetectionStatus.detected) {
    if (before?.status == DetectionStatus.detected) return null;
    return (message: unsafeWifiWarning(current)!, unsafe: true);
  }
  bool onWifi(DetectionResult? r) => r?.evidence.any((e) => e.key == 'on_wifi' && e.value == true) ?? false;
  if (!onWifi(now) || onWifi(before)) return null;
  final type = now.evidence.where((e) => e.key == 'security_type').map((e) => e.value).firstOrNull;
  return (message: type == null ? 'Connected to Wi-Fi.' : 'Connected to Wi-Fi ($type).', unsafe: false);
}

/// The old "close the app" reaction, kept only behind a setting that is off
/// by default: `true` when [closeOnUsbDebugging] is on and USB debugging has
/// just turned on (or is on at the first reading).
bool shouldCloseApp({
  required RaspLeanState? previous,
  required RaspLeanState current,
  required bool closeOnUsbDebugging,
}) =>
    closeOnUsbDebugging &&
    current.usb.usbDebuggingEnabled == true &&
    previous?.usb.usbDebuggingEnabled != true;
