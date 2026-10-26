import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:rasp_shield/sdk/core/core.dart' show DetectionStatus;
import 'package:rasp_shield/sdk/lean_session.dart' show RaspLeanState;

import 'feature_catalog.dart';

/// One change of a feature's verdict, for the detection log on its page.
class FeatureLogEntry {
  final DateTime at;
  /// `null`: the feature was switched off.
  final DetectionStatus? status;
  final String? note;

  const FeatureLogEntry(this.at, this.status, [this.note]);
}

/// Which of the 43 features are on, the latest session state and each
/// feature's recent verdict changes. Owned by the main screen, which
/// restarts the session with [enabled] whenever it changes (only one native
/// session runs at a time). Not saved: every launch starts with
/// [defaultEnabledFeatureIds], like the other trial settings.
class FeatureLab extends ChangeNotifier {
  FeatureLab({Set<String>? enabled}) : _enabled = {...(enabled ?? defaultEnabledFeatureIds)};

  /// Entries kept per feature.
  static const logLength = 20;

  Set<String> _enabled;
  RaspLeanState _state = RaspLeanState.initial;
  bool _applying = false;
  final _log = <String, List<FeatureLogEntry>>{};
  final _lastStatus = <String, DetectionStatus?>{};

  /// Called by the owner when [enabled] changes; restarts the session.
  Future<void> Function()? onEnabledChanged;

  /// Runs every enabled detector now (the session's refreshNow).
  Future<void> Function()? onRefresh;

  /// Asks the backend for a new signed remote config now (the session's
  /// refreshRemoteConfigNow), for the remote configuration page.
  Future<void> Function()? onRefreshRemoteConfig;

  /// The controls a feature's page shows under "Try it" (phone permission,
  /// share location, clipboard copy / paste, TLS pin, ...), built by the
  /// owner from its own state. Empty or `null`: no "Try it" panel.
  List<Widget> Function(BuildContext context, String id)? tryItPanel;

  /// Lets the pages rebuild after the owner changed something they show
  /// (e.g. location sharing).
  void ownerChanged() => notifyListeners();

  Set<String> get enabled => Set.unmodifiable(_enabled);
  bool isEnabled(String id) => _enabled.contains(id);
  RaspLeanState get state => _state;

  /// `true` while the session restarts with a new set of features.
  bool get applying => _applying;
  set applying(bool value) {
    if (_applying == value) return;
    _applying = value;
    notifyListeners();
  }

  /// Newest first.
  List<FeatureLogEntry> logFor(String id) => List.unmodifiable(_log[id] ?? const []);

  Future<void> setEnabled(String id, bool on) => setManyEnabled({id}, on);

  Future<void> setManyEnabled(Iterable<String> ids, bool on) async {
    final next = {..._enabled};
    on ? next.addAll(ids) : next.removeAll(ids);
    if (setEquals(next, _enabled)) return;
    final now = DateTime.now();
    for (final id in ids) {
      if (!on && _enabled.contains(id)) {
        _add(id, FeatureLogEntry(now, null, 'Switched off'));
        _lastStatus.remove(id);
      }
    }
    _enabled = next;
    notifyListeners();
    await onEnabledChanged?.call();
  }

  /// A new session state: logs every enabled feature whose verdict changed,
  /// and every clipboard copy (its count is reset after each check).
  void update(RaspLeanState state) {
    _state = state;
    final now = DateTime.now();
    for (final id in _enabled) {
      final verdict = featureVerdict(state, id);
      if (verdict.status == null) continue;
      if (!_lastStatus.containsKey(id) || _lastStatus[id] != verdict.status) {
        _lastStatus[id] = verdict.status;
        _add(id, FeatureLogEntry(now, verdict.status, verdict.reason));
      }
    }
    if (_enabled.contains('clipboard_protection') && clipboardCopySeen(state)) {
      _add('clipboard_protection', FeatureLogEntry(now, DetectionStatus.detected,
          'Copy observed (${state.clipboardEvidence.changeCount}) and clipboard cleared'));
    }
    notifyListeners();
  }

  void _add(String id, FeatureLogEntry entry) {
    final list = _log.putIfAbsent(id, () => []);
    list.insert(0, entry);
    if (list.length > logLength) list.removeRange(logLength, list.length);
  }
}
