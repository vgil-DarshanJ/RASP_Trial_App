// "Check connection" in Backend Sync: can this phone reach the backend that
// issued the pasted credential? Calls `<origin>/healthz` (no key, no secret)
// and explains the answer — in particular that "localhost" on a phone is the
// phone itself, so a localhost credential needs `adb reverse` over USB.
import 'dart:async';
import 'dart:io';

/// Checks `<origin>/healthz` and returns a sentence for the screen.
/// Replaceable in tests.
Future<String> Function(String origin) checkBackendConnection = (origin) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 5);
  try {
    final request = await client.getUrl(Uri.parse('$origin/healthz')).timeout(const Duration(seconds: 6));
    final response = await request.close().timeout(const Duration(seconds: 6));
    await response.drain<void>();
    return describeBackendCheck(origin, status: response.statusCode);
  } catch (e) {
    return describeBackendCheck(origin, error: e is TimeoutException ? 'no answer within 6 s' : e.runtimeType.toString());
  } finally {
    client.close(force: true);
  }
};

/// The message for one check: [status] when the backend answered, [error] when not. Pure.
String describeBackendCheck(String origin, {int? status, String? error}) {
  final uri = Uri.parse(origin);
  final host = uri.hasPort ? '${uri.host}:${uri.port}' : uri.host;
  if (status != null) {
    if (status == 200) return 'Reachable: $host answered /healthz (HTTP 200).';
    if (status == 503) return 'Reachable, but $host reports a problem (HTTP 503: its database or Redis is down).';
    return '$host answered HTTP $status on /healthz — is this the RASP Shield backend?';
  }
  final isLocal = uri.host == 'localhost' || uri.host == '127.0.0.1';
  final hint = isLocal
      ? 'On a phone, "localhost" is the phone itself. Connect the phone by USB and run on the PC: '
          'adb reverse tcp:${uri.hasPort ? uri.port : 80} tcp:${uri.hasPort ? uri.port : 80}'
      : 'The phone must be on the same network as $host, and that computer\'s firewall must allow '
          'port ${uri.hasPort ? uri.port : (uri.scheme == 'https' ? 443 : 80)}. If this is not your backend, '
          'paste a credential issued by your own dashboard.';
  return 'Cannot reach $host (${error ?? 'unknown error'}). $hint';
}
