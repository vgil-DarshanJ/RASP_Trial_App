import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:rasp_shield/sdk/core/core.dart' show DetectionResult;
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLeanState;

/// DEBUG BUILDS ONLY. Writes every detector result as one JSON line to
/// logcat with tag RASP_RESULT (through the debug-only native channel in
/// android/app/src/debug), for phone smoke tests:
///
///     adb logcat -d -s RASP_RESULT
///
/// A line is written when a detector first reports and whenever its status,
/// reason or evidence changes — not on every 4 s tick. main.dart creates this
/// only when `kDebugMode` is true, so release builds do not contain it; their
/// native side is a no-op as well (android/app/src/release).
class DebugResultLogger {
  DebugResultLogger({Future<void> Function(String line)? sink}) : _sink = sink ?? _logcat;

  static const channelName = 'rasp_trial/debug_result_log';
  static const _channel = MethodChannel(channelName);

  final Future<void> Function(String line) _sink;
  final _lastLineById = <String, String>{};

  /// One JSON line: `{"id", "status", "reason", "evidence": [{"key", "value", "note"}]}`.
  static String resultLine(DetectionResult result) => jsonEncode(
        {
          'id': result.detectorId,
          'status': result.status.name.toUpperCase(),
          'reason': result.unavailableReason,
          'evidence': [
            for (final e in result.evidence) {'key': e.key, 'value': e.value, 'note': e.note},
          ],
        },
        toEncodable: (Object? value) => '$value',
      );

  /// The four basic controls, as lines of the same shape (status ON / OFF / UNKNOWN).
  static List<String> controlLines(RaspLeanState state) {
    String status(bool? v) => v == null ? 'UNKNOWN' : (v ? 'ON' : 'OFF');
    String line(String id, bool? value, [Map<String, Object?> extra = const {}]) => jsonEncode({
          'id': id,
          'status': status(value),
          'reason': null,
          'evidence': [
            {'key': 'value', 'value': value, 'note': null},
            for (final e in extra.entries) {'key': e.key, 'value': e.value, 'note': null},
          ],
        });
    return [
      line('screenshot_protection', state.screenshotActive),
      line('usb_connection', state.usb.usbConnected, {'device_count': state.usb.connectedDeviceCount}),
      line('adb_enabled', state.usb.usbDebuggingEnabled, {'developer_mode': state.usb.developerModeEnabled}),
      line('clipboard_protection', state.clipboardActive, {'change_count': state.clipboardEvidence.changeCount}),
    ];
  }

  /// Lines for results that are new or changed since the last call.
  List<String> changedLines(RaspLeanState state) {
    final current = <String, String>{
      for (final line in controlLines(state)) (jsonDecode(line) as Map)['id'] as String: line,
      for (final e in state.extendedDetectors.entries) e.key: resultLine(e.value),
    };
    final changed = <String>[
      for (final e in current.entries)
        if (_lastLineById[e.key] != e.value) e.value,
    ];
    _lastLineById.addAll(current);
    return changed;
  }

  void log(RaspLeanState state) {
    for (final line in changedLines(state)) {
      _sink(line);
    }
  }

  static Future<void> _logcat(String line) async {
    try {
      await _channel.invokeMethod<void>('log', line);
    } catch (_) {
      // No native logger (e.g. a widget test): nothing to do.
    }
  }
}
