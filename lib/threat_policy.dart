import 'package:rasp_shield/sdk/lean_session.dart' show RaspLeanState;

/// Device-posture warnings for the banner at the top of the main screen.
/// Developer options, USB debugging and a USB connection are warned about —
/// the app keeps running.
List<String> postureWarnings(RaspLeanState state) => [
      if (state.usb.developerModeEnabled == true) 'Developer options are unlocked on this device.',
      if (state.usb.usbDebuggingEnabled == true) 'USB debugging (ADB) is enabled.',
      if (state.usb.usbConnected == true) 'A USB cable or dock is connected.',
    ];

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
