import 'dart:async';

import 'package:flutter/material.dart';
import 'package:rasp_shield/sdk/core/core.dart' show DetectionResult, DetectionStatus;
import 'package:rasp_shield/sdk/lean_session.dart';

/// Detector ids this trial app turns on (see `trialConfig` in main.dart), in
/// display order. A detector with no result yet is shown as "waiting".
const trialDetectorIds = <String>[
  // Device integrity
  'root_jailbreak', 'emulator', 'device_binding', 'clone', 'developer_mode',
  'device_lock_missing', 'secure_hardware_unavailable', 'device_fingerprint',
  'device_state_attestation', 'sim_change', 'mock_location', 'time_spoofing',
  // Runtime protection
  'frida', 'debugger', 're_tools', 'hook_detection', 'risky_app', 'malware_reputation',
  // App integrity
  'tamper', 'untrusted_install_source', 'task_hijack',
  // Network
  'vpn', 'mitm', 'high_risk_ip', 'unsafe_wifi',
  // Privacy & screen
  'overlay', 'accessibility', 'external_display', 'screen_recording',
  'vishing_call', 'third_party_keyboard',
];

/// Every enabled detector with its current status, reason and full evidence,
/// plus the evidence-envelope delivery counters — for reading results on a
/// phone. Updates live from the session and re-reads the counters every 3 s.
class DetectorResultsScreen extends StatefulWidget {
  final RaspLeanSession session;

  const DetectorResultsScreen({super.key, required this.session});

  @override
  State<DetectorResultsScreen> createState() => _DetectorResultsScreenState();
}

class _DetectorResultsScreenState extends State<DetectorResultsScreen> {
  late RaspLeanState _state = widget.session.current;
  StreamSubscription<RaspLeanState>? _sub;
  Timer? _statsTimer;
  Map<String, int> _stats = const {};
  DateTime? _statsAt;

  @override
  void initState() {
    super.initState();
    _sub = widget.session.stateStream.listen((s) {
      if (mounted) setState(() => _state = s);
    });
    _readStats();
    _statsTimer = Timer.periodic(const Duration(seconds: 3), (_) => _readStats());
  }

  Future<void> _readStats() async {
    final stats = await RaspLeanSession.deliveryStats();
    if (mounted) setState(() { _stats = stats; _statsAt = DateTime.now(); });
  }

  @override
  void dispose() {
    _sub?.cancel();
    _statsTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final results = _state.extendedDetectors;
    final extra = results.keys.where((id) => !trialDetectorIds.contains(id)).toList()..sort();
    final ids = [...trialDetectorIds, ...extra];
    final counts = <DetectionStatus, int>{};
    for (final r in results.values) {
      counts[r.status] = (counts[r.status] ?? 0) + 1;
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Detector results'),
        actions: [
          IconButton(
            tooltip: 'Run all detectors now',
            icon: const Icon(Icons.refresh),
            onPressed: () async {
              await widget.session.refreshNow();
              await _readStats();
            },
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          _DeliveryCard(stats: _stats, readAt: _statsAt),
          const SizedBox(height: 8),
          _Summary(total: ids.length, reported: results.length, counts: counts),
          const SizedBox(height: 8),
          _ControlsCard(state: _state),
          const SizedBox(height: 8),
          for (final id in ids) _DetectorTile(id: id, result: results[id]),
        ],
      ),
    );
  }
}

class _DeliveryCard extends StatelessWidget {
  final Map<String, int> stats;
  final DateTime? readAt;

  const _DeliveryCard({required this.stats, required this.readAt});

  static const _labels = <String, String>{
    'delivered': 'Delivered (2xx)',
    'dropped_invalid': 'Dropped — invalid (400/422)',
    'dropped_expired': 'Dropped — older than 7 days',
    'dropped_unauthorized': 'Dropped — 401 after re-registration',
    'dropped_rejected': 'Dropped — other 4xx',
    're_registrations': 'Device re-registrations',
  };

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Envelope delivery (since app start)', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            if (stats.isEmpty)
              const Text('No counters from the native side yet.', style: TextStyle(color: Colors.black54))
            else
              for (final e in _labels.entries)
                Row(children: [
                  Expanded(child: Text(e.value, style: const TextStyle(fontSize: 13))),
                  Text('${stats[e.key] ?? 0}', style: const TextStyle(fontWeight: FontWeight.w600)),
                ]),
            if (readAt != null)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('Read at ${_time(readAt!)}', style: const TextStyle(fontSize: 11, color: Colors.black45)),
              ),
          ],
        ),
      ),
    );
  }
}

class _Summary extends StatelessWidget {
  final int total;
  final int reported;
  final Map<DetectionStatus, int> counts;

  const _Summary({required this.total, required this.reported, required this.counts});

  @override
  Widget build(BuildContext context) {
    String n(DetectionStatus s) => '${counts[s] ?? 0}';
    return Text(
      '$reported of $total reported — detected ${n(DetectionStatus.detected)}, '
      'secure ${n(DetectionStatus.secure)}, unknown ${n(DetectionStatus.unknown)}, '
      'unavailable ${n(DetectionStatus.unavailable)}, error ${n(DetectionStatus.error)}',
      style: const TextStyle(fontSize: 13),
    );
  }
}

class _ControlsCard extends StatelessWidget {
  final RaspLeanState state;

  const _ControlsCard({required this.state});

  @override
  Widget build(BuildContext context) {
    String v(Object? x) => x == null ? 'not reported' : '$x';
    final rows = <(String, String)>[
      ('screenshot_protection (FLAG_SECURE active)', v(state.screenshotActive)),
      ('usb_connection', v(state.usb.usbConnected)),
      ('adb_enabled', v(state.usb.usbDebuggingEnabled)),
      ('developer mode', v(state.usb.developerModeEnabled)),
      ('clipboard_protection (active / changes)', '${v(state.clipboardActive)} / ${state.clipboardEvidence.changeCount}'),
    ];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Basic controls', style: TextStyle(fontWeight: FontWeight.bold)),
            for (final (label, value) in rows)
              Row(children: [
                Expanded(child: Text(label, style: const TextStyle(fontSize: 13))),
                Text(value, style: const TextStyle(fontSize: 13)),
              ]),
          ],
        ),
      ),
    );
  }
}

class _DetectorTile extends StatelessWidget {
  final String id;
  final DetectionResult? result;

  const _DetectorTile({required this.id, required this.result});

  @override
  Widget build(BuildContext context) {
    final r = result;
    final (Color color, String label) = switch (r?.status) {
      DetectionStatus.detected => (Colors.red, 'DETECTED'),
      DetectionStatus.secure => (Colors.green, 'SECURE'),
      DetectionStatus.unavailable => (Colors.grey, 'UNAVAILABLE'),
      DetectionStatus.unknown => (Colors.orange, 'UNKNOWN'),
      DetectionStatus.error => (Colors.deepOrange, 'ERROR'),
      null => (Colors.black38, 'waiting for first result'),
    };
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Expanded(
                child: Text(
                  r == null ? id : '${r.title}  ($id)',
                  style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
                ),
              ),
              Text(label, style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 12)),
            ]),
            if (r?.unavailableReason != null)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text('Reason: ${r!.unavailableReason}', style: const TextStyle(fontSize: 12, color: Colors.black54)),
              ),
            if (r != null)
              for (final e in r.evidence)
                Padding(
                  padding: const EdgeInsets.only(top: 2),
                  child: SelectableText(
                    '${e.key} = ${e.value}${e.note == null ? '' : '  (${e.note})'}',
                    style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
                  ),
                ),
            if (r != null)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text('Observed ${_time(r.observedAt.toLocal())}', style: const TextStyle(fontSize: 11, color: Colors.black38)),
              ),
          ],
        ),
      ),
    );
  }
}

String _time(DateTime t) =>
    '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';
