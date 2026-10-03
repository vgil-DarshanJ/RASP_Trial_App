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
Future<RaspLocationSnapshot?> captureLocationSnapshot() async {
  try {
    if (!await Geolocator.isLocationServiceEnabled()) return null;

    var permission = await Geolocator.checkPermission();
    if (permission == LocationPermission.denied) {
      // Only requests once per call, never loops — a user who denies it
      // stays denied for this run rather than being nagged repeatedly.
      permission = await Geolocator.requestPermission();
    }
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
      capturedAt: DateTime.now().toUtc(),
    );
  } catch (_) {
    // Timeout, platform channel error, or any other failure — degrade to
    // "nothing this cycle," never crash whatever called this.
    return null;
  }
}
