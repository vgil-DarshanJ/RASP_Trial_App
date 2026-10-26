import 'package:flutter/material.dart';
import 'package:rasp_shield/sdk/core/core.dart' show DetectionSeverity, DetectionStatus;
import 'package:rasp_shield/sdk/lean_session.dart'
    show RaspDetectorDescriptor, RaspRemoteConfigStatus, RaspThreatCategoryHeading;

import 'detector_catalog.dart';
import 'feature_catalog.dart';
import 'feature_lab.dart';

/// The 43 features in list order: grouped under the same category headings,
/// in the same order, as the other screens (detector_catalog.dart).
final featureDisplayOrder = <String>[
  for (final (_, ids) in groupByCategory(allFeatureIds)) ...ids,
];

/// 1-based number shown on a feature's tile and page.
int featureNumber(String id) => featureDisplayOrder.indexOf(id) + 1;

/// Colour, icon and label for a verdict; [isProtection] words SECURE as
/// "Protected". `null` status: enabled, no result yet.
(Color, IconData, String) verdictStyle(DetectionStatus? status, {required bool enabled, bool isProtection = false}) {
  if (!enabled) return (Colors.blueGrey, Icons.power_settings_new, 'Off');
  return switch (status) {
    null => (Colors.blue, Icons.hourglass_top, 'Checking…'),
    DetectionStatus.detected => (Colors.red.shade700, Icons.warning_amber_rounded, 'Detected'),
    DetectionStatus.secure when isProtection => (Colors.green.shade700, Icons.shield, 'Protected'),
    DetectionStatus.secure => (Colors.green.shade700, Icons.check_circle, 'Secure'),
    DetectionStatus.unavailable when isProtection => (Colors.orange.shade800, Icons.shield_outlined, 'Not protected'),
    DetectionStatus.unavailable => (Colors.grey.shade600, Icons.help_outline, 'Unavailable'),
    DetectionStatus.unknown => (Colors.orange.shade800, Icons.question_mark, 'Unknown'),
    DetectionStatus.error => (Colors.orange.shade800, Icons.error_outline, 'Error'),
  };
}

String _time(DateTime at) {
  String two(int n) => n.toString().padLeft(2, '0');
  return '${two(at.hour)}:${two(at.minute)}:${two(at.second)}';
}

// ── Feature list ─────────────────────────────────────────────────────────────

/// The Feature lab, the app's home: one tile per feature with its live
/// status. Tapping a tile opens that feature's page with Enable / Disable.
/// [header] goes above the list (e.g. Backend Sync), [actions] in the app bar.
class FeatureListScreen extends StatelessWidget {
  final FeatureLab lab;
  final List<Widget> actions;
  final List<Widget> header;

  const FeatureListScreen({super.key, required this.lab, this.actions = const [], this.header = const []});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: lab,
      builder: (context, _) {
        final enabledCount = featureDisplayOrder.where(lab.isEnabled).length;
        final threats = [
          for (final id in featureDisplayOrder)
            if (lab.isEnabled(id) && featureVerdict(lab.state, id).isThreat) id,
        ];
        return Scaffold(
          appBar: AppBar(
            title: Text('Feature lab (${featureDisplayOrder.length})'),
            actions: [
              IconButton(
                tooltip: 'Run all checks now',
                icon: const Icon(Icons.refresh),
                onPressed: () => lab.onRefresh?.call(),
              ),
              ...actions,
            ],
          ),
          body: RefreshIndicator(
            onRefresh: () async => lab.onRefresh?.call(),
            child: ListView(
              padding: const EdgeInsets.fromLTRB(12, 12, 12, 24),
              children: [
                ...header,
                _LabSummary(
                  total: featureDisplayOrder.length,
                  enabled: enabledCount,
                  threats: threats.length,
                  applying: lab.applying,
                  onEnableAll: () => lab.setManyEnabled(featureDisplayOrder, true),
                  onDisableAll: () => lab.setManyEnabled(featureDisplayOrder, false),
                ),
                for (final (heading, ids) in groupByCategory(featureDisplayOrder)) ...[
                  Padding(
                    padding: const EdgeInsets.fromLTRB(4, 16, 4, 6),
                    child: Text(heading, style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
                  ),
                  for (final id in ids) _FeatureTile(lab: lab, id: id),
                ],
              ],
            ),
          ),
        );
      },
    );
  }
}

class _LabSummary extends StatelessWidget {
  final int total;
  final int enabled;
  final int threats;
  final bool applying;
  final VoidCallback onEnableAll;
  final VoidCallback onDisableAll;

  const _LabSummary({
    required this.total,
    required this.enabled,
    required this.threats,
    required this.applying,
    required this.onEnableAll,
    required this.onDisableAll,
  });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      color: scheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('$total on-device features', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 4),
            Text('$enabled enabled · ${total - enabled} off', key: const Key('lab-enabled-count')),
            Text(
              threats == 0 ? 'No threats detected right now' : '$threats threat${threats == 1 ? '' : 's'} detected',
              key: const Key('lab-threat-count'),
              style: TextStyle(
                color: threats == 0 ? Colors.green.shade800 : Colors.red.shade700,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 4),
            const Text('Tap a feature to enable or disable it and see it detect live.', style: TextStyle(fontSize: 12)),
            if (applying) const Padding(padding: EdgeInsets.only(top: 8), child: LinearProgressIndicator()),
            const SizedBox(height: 8),
            Wrap(spacing: 8, children: [
              FilledButton.tonal(key: const Key('lab-enable-all'), onPressed: onEnableAll, child: const Text('Enable all')),
              OutlinedButton(key: const Key('lab-disable-all'), onPressed: onDisableAll, child: const Text('Disable all')),
            ]),
          ],
        ),
      ),
    );
  }
}

class _FeatureTile extends StatelessWidget {
  final FeatureLab lab;
  final String id;

  const _FeatureTile({required this.lab, required this.id});

  @override
  Widget build(BuildContext context) {
    final feature = featureById(id);
    final enabled = lab.isEnabled(id);
    final verdict = featureVerdict(lab.state, id);
    final (color, icon, label) = verdictStyle(verdict.status, enabled: enabled, isProtection: feature.isProtection);
    return Card(
      key: Key('feature-tile-$id'),
      margin: const EdgeInsets.symmetric(vertical: 3),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: verdict.isThreat && enabled ? BorderSide(color: color, width: 1.5) : BorderSide.none,
      ),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: enabled ? Theme.of(context).colorScheme.primary : Colors.blueGrey.shade100,
          foregroundColor: enabled ? Colors.white : Colors.blueGrey,
          child: Text('${featureNumber(id)}', style: const TextStyle(fontWeight: FontWeight.bold)),
        ),
        title: Text(feature.title, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Row(children: [
          Icon(feature.icon, size: 14, color: Colors.black45),
          const SizedBox(width: 4),
          Expanded(child: Text(id, style: const TextStyle(fontSize: 11, color: Colors.black45))),
        ]),
        trailing: _StatusChip(color: color, icon: icon, label: label),
        onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(
          builder: (_) => FeatureDetailScreen(lab: lab, id: id),
        )),
      ),
    );
  }
}

class _StatusChip extends StatelessWidget {
  final Color color;
  final IconData icon;
  final String label;

  const _StatusChip({required this.color, required this.icon, required this.label});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(16)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 14, color: Colors.white),
        const SizedBox(width: 4),
        Text(label, style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600)),
      ]),
    );
  }
}

// ── Feature page ─────────────────────────────────────────────────────────────

/// One feature: Enable / Disable, the live result, how to show it working,
/// evidence and a log of its verdict changes. Previous / Next step through
/// all 43 in list order.
class FeatureDetailScreen extends StatelessWidget {
  final FeatureLab lab;
  final String id;

  const FeatureDetailScreen({super.key, required this.lab, required this.id});

  void _open(BuildContext context, String other) => Navigator.of(context).pushReplacement(
        PageRouteBuilder<void>(
          pageBuilder: (_, _, _) => FeatureDetailScreen(lab: lab, id: other),
          transitionDuration: Duration.zero,
        ),
      );

  @override
  Widget build(BuildContext context) {
    final feature = featureById(id);
    final descriptor = RaspDetectorDescriptor.forId(id);
    final index = featureDisplayOrder.indexOf(id);
    final previous = index > 0 ? featureDisplayOrder[index - 1] : null;
    final next = index < featureDisplayOrder.length - 1 ? featureDisplayOrder[index + 1] : null;

    return ListenableBuilder(
      listenable: lab,
      builder: (context, _) {
        final enabled = lab.isEnabled(id);
        final verdict = featureVerdict(lab.state, id);
        return Scaffold(
          appBar: AppBar(title: Text('Feature ${index + 1} of ${featureDisplayOrder.length}')),
          body: ListView(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
            children: [
              _Header(feature: feature, category: descriptor.category.heading, severity: descriptor.severity),
              const SizedBox(height: 16),
              _EnableCard(
                enabled: enabled,
                applying: lab.applying,
                onChanged: (on) => lab.setEnabled(id, on),
              ),
              const SizedBox(height: 12),
              _LiveResult(feature: feature, enabled: enabled, verdict: verdict, onRunNow: () => lab.onRefresh?.call()),
              const SizedBox(height: 12),
              _Section(title: 'What it protects against', children: [
                Text(feature.summary),
                if (feature.needs != null) ...[
                  const SizedBox(height: 8),
                  Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    const Icon(Icons.info_outline, size: 16, color: Colors.black54),
                    const SizedBox(width: 6),
                    Expanded(child: Text('Needs: ${feature.needs}', style: const TextStyle(fontSize: 13, color: Colors.black54))),
                  ]),
                ],
              ]),
              ..._extras(context, enabled),
              const SizedBox(height: 12),
              _Section(title: 'How to show it working', children: [
                for (final (i, step) in feature.howToShow.indexed)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 3),
                    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      CircleAvatar(radius: 10, child: Text('${i + 1}', style: const TextStyle(fontSize: 11))),
                      const SizedBox(width: 8),
                      Expanded(child: Text(step)),
                    ]),
                  ),
              ]),
              const SizedBox(height: 12),
              _Section(title: 'Evidence', children: [
                if (!enabled)
                  const Text('Off — enable the feature to collect evidence.', style: TextStyle(color: Colors.black54))
                else if (verdict.evidence.isEmpty)
                  const Text('No evidence items in the latest result.', style: TextStyle(color: Colors.black54))
                else
                  for (final e in verdict.evidence)
                    Padding(
                      padding: const EdgeInsets.symmetric(vertical: 2),
                      child: Text('${e.key}: ${e.value}${e.note == null ? '' : '  — ${e.note}'}',
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                    ),
              ]),
              const SizedBox(height: 12),
              _DetectionLog(entries: lab.logFor(id), isProtection: feature.isProtection),
            ],
          ),
          bottomNavigationBar: SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(12, 4, 12, 8),
              child: Row(children: [
                Expanded(
                  child: OutlinedButton.icon(
                    key: const Key('feature-previous'),
                    onPressed: previous == null ? null : () => _open(context, previous),
                    icon: const Icon(Icons.chevron_left),
                    label: const Text('Previous'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.tonalIcon(
                    key: const Key('feature-next'),
                    onPressed: next == null ? null : () => _open(context, next),
                    icon: const Icon(Icons.chevron_right),
                    label: const Text('Next'),
                  ),
                ),
              ]),
            ),
          ),
        );
      },
    );
  }

  /// Controls some features need to be shown on a phone: the owner's
  /// "Try it" panel (FeatureLab.tryItPanel), or the remote config status.
  List<Widget> _extras(BuildContext context, bool enabled) {
    final panel = lab.tryItPanel?.call(context, id) ?? const <Widget>[];
    if (panel.isNotEmpty) {
      return [
        const SizedBox(height: 12),
        _Section(title: 'Try it', children: panel),
      ];
    }
    switch (id) {
      case 'remote_config_rejected':
        final version = lab.state.remoteConfigVersion;
        return [
          const SizedBox(height: 12),
          _Section(title: 'Try it', children: [
            Text('Remote config: ${remoteConfigStatusLabel(lab.state.remoteConfigStatus)}',
                key: const Key('feature-remote-config-status')),
            Text(version == null ? 'No config applied' : 'Applied version: $version',
                key: const Key('feature-remote-config-version'),
                style: const TextStyle(fontSize: 13, color: Colors.black54)),
            if (lab.onRefreshRemoteConfig != null) ...[
              const SizedBox(height: 8),
              OutlinedButton.icon(
                key: const Key('feature-remote-config-refresh'),
                onPressed: enabled ? () => lab.onRefreshRemoteConfig!() : null,
                icon: const Icon(Icons.cloud_sync),
                label: const Text('Check for a new config now'),
              ),
            ],
          ]),
        ];
    }
    return const [];
  }
}

/// Plain wording for the session's remote configuration status.
String remoteConfigStatusLabel(RaspRemoteConfigStatus status) => switch (status) {
      RaspRemoteConfigStatus.off => 'off',
      RaspRemoteConfigStatus.unavailable => 'unavailable (no credential or no config public key)',
      RaspRemoteConfigStatus.waiting => 'waiting (nothing received or published yet)',
      RaspRemoteConfigStatus.applied => 'applied',
      RaspRemoteConfigStatus.rejected => 'last config refused — the previous settings stay',
      RaspRemoteConfigStatus.expired => 'expired — the app\'s own settings apply',
    };

class _Header extends StatelessWidget {
  final TrialFeature feature;
  final String category;
  final DetectionSeverity severity;

  const _Header({required this.feature, required this.category, required this.severity});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Row(children: [
      CircleAvatar(
        radius: 28,
        backgroundColor: scheme.primaryContainer,
        child: Icon(feature.icon, size: 30, color: scheme.primary),
      ),
      const SizedBox(width: 14),
      Expanded(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(feature.title, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          Wrap(spacing: 6, runSpacing: 4, children: [
            _Tag(category),
            _Tag('Severity: ${severity.name}'),
            _Tag(feature.id),
          ]),
        ]),
      ),
    ]);
  }
}

class _Tag extends StatelessWidget {
  final String text;
  const _Tag(this.text);

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(text, style: const TextStyle(fontSize: 11)),
      );
}

class _EnableCard extends StatelessWidget {
  final bool enabled;
  final bool applying;
  final ValueChanged<bool> onChanged;

  const _EnableCard({required this.enabled, required this.applying, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(enabled ? 'Feature is ENABLED' : 'Feature is DISABLED',
              key: const Key('feature-enabled-label'),
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.bold,
                    color: enabled ? Colors.green.shade800 : Colors.blueGrey,
                  )),
          const SizedBox(height: 12),
          SegmentedButton<bool>(
            key: const Key('feature-enable-toggle'),
            segments: const [
              ButtonSegment(value: true, label: Text('Enable'), icon: Icon(Icons.power_settings_new)),
              ButtonSegment(value: false, label: Text('Disable'), icon: Icon(Icons.block)),
            ],
            selected: {enabled},
            onSelectionChanged: (selection) => onChanged(selection.first),
          ),
          if (applying) ...[
            const SizedBox(height: 10),
            const LinearProgressIndicator(),
            const SizedBox(height: 4),
            const Text('Applying — restarting the protection session…', style: TextStyle(fontSize: 12)),
          ],
        ]),
      ),
    );
  }
}

class _LiveResult extends StatelessWidget {
  final TrialFeature feature;
  final bool enabled;
  final FeatureVerdict verdict;
  final VoidCallback onRunNow;

  const _LiveResult({required this.feature, required this.enabled, required this.verdict, required this.onRunNow});

  @override
  Widget build(BuildContext context) {
    final (color, icon, label) = verdictStyle(verdict.status, enabled: enabled, isProtection: feature.isProtection);
    final headline = !enabled
        ? 'Not running'
        : switch (verdict.status) {
            null => 'Waiting for the first check…',
            DetectionStatus.detected => 'THREAT DETECTED',
            DetectionStatus.secure => feature.isProtection ? 'Protection is active' : 'No threat found',
            _ => label,
          };
    final detail = !enabled
        ? 'Enable the feature to start checking.'
        : verdict.reason ?? (verdict.isThreat ? 'Reported by the on-device engine just now.' : 'Checked every 4 seconds and when the app comes back.');
    return AnimatedContainer(
      key: const Key('feature-live-result'),
      duration: const Duration(milliseconds: 300),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color, width: verdict.isThreat && enabled ? 2 : 1),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Icon(icon, color: color, size: 36),
          const SizedBox(width: 12),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('LIVE RESULT', style: TextStyle(fontSize: 11, letterSpacing: 1.2, color: color)),
              Text(headline,
                  key: const Key('feature-headline'),
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: color)),
            ]),
          ),
          _StatusChip(color: color, icon: icon, label: label),
        ]),
        const SizedBox(height: 8),
        Text(detail, style: const TextStyle(fontSize: 13)),
        if (enabled)
          Align(
            alignment: Alignment.centerRight,
            child: TextButton.icon(
              key: const Key('feature-run-now'),
              onPressed: onRunNow,
              icon: const Icon(Icons.refresh),
              label: const Text('Run check now'),
            ),
          ),
      ]),
    );
  }
}

class _Section extends StatelessWidget {
  final String title;
  final List<Widget> children;

  const _Section({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surfaceContainerLow,
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(title, style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          ...children,
        ]),
      ),
    );
  }
}

class _DetectionLog extends StatelessWidget {
  final List<FeatureLogEntry> entries;
  final bool isProtection;

  const _DetectionLog({required this.entries, required this.isProtection});

  @override
  Widget build(BuildContext context) {
    return _Section(title: 'Detection log', children: [
      if (entries.isEmpty)
        const Text('Nothing yet. Changes of the result appear here with the time, newest first.',
            style: TextStyle(color: Colors.black54))
      else
        for (final entry in entries)
          Builder(builder: (context) {
            final (color, icon, label) = verdictStyle(entry.status, enabled: entry.status != null, isProtection: isProtection);
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 3),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(_time(entry.at), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                const SizedBox(width: 8),
                Icon(icon, size: 16, color: color),
                const SizedBox(width: 4),
                Expanded(
                  child: Text('$label${entry.note == null ? '' : ' — ${entry.note}'}',
                      style: TextStyle(fontSize: 13, color: color, fontWeight: FontWeight.w600)),
                ),
              ]),
            );
          }),
    ]);
  }
}
