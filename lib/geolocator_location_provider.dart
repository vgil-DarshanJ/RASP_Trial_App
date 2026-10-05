import 'package:geolocator/geolocator.dart';
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLocationSnapshot;

/// This app's own way of obtaining a location reading to hand to
/// [RaspLeanSession.currentLocation] — the SDK itself contains no
/// geolocation code at all (see [RaspLocationSnapshot]'s doc); this plain
/// function is entirely this app's responsibility, using whatever
/// mechanism it prefers (`geolocator` here).
///
/// Never throws, never fabricates a coordinate. A denied/unavailable
/// permission or disabled location service returns `null` — the caller
/// should simply leave `currentLocation` at its previous value (or unset)
/// when this returns `null`, never guess.
///
/// [shareWithBackend] marks the fix as shared with the backend (the user's
/// opt-in, Task 6.0); otherwise it is only used on the device.
Future<RaspLocationSnapshot?> captureLocationSnapshot({bool shareWithBackend = false}) async {
  try {
    if (!await Geolocator.isLocationServiceEnabled()) return null;

    // Checks only: the permission is requested by the "Share location"
    // switch (main.dart) before this is called.
    final permission = await Geolocator.checkPermission();
    if (permission == LocationPermission.denied ||
        permission == LocationPermission.deniedForever) {
      return null;
    }

    final position = await Geolocator.getCurrentPosition(
      locationSettings: const LocationSettings(
        accuracy: LocationAccuracy.high,
        timeLimit: Duration(seconds: 8),
      ),
    );

    return RaspLocationSnapshot(
      latitude: position.latitude,
      longitude: position.longitude,
      accuracyMeters: position.accuracy,
      // The fix's own time, so the SDK can reject a stale fix (> 2 min).
      capturedAt: position.timestamp.toUtc(),
      // Android's own mock flag for this fix — what mock_location decides on.
      isMock: position.isMocked,
      shareWithBackend: shareWithBackend,
    );
  } catch (_) {
    // Timeout, platform channel error, or any other failure — degrade to
    // "nothing this cycle," never crash whatever called this.
    return null;
  }
}
