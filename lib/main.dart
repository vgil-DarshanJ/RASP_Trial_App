import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show SystemNavigator;
import 'package:rasp_shield/sdk/core/core.dart'
    show DetectionResult, DetectionStatus, DetectionStatusX;
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';
import 'package:rasp_shield/sdk/lean_session.dart';
import 'package:rasp_shield/sdk/security_controls.dart';

import 'detector_results_screen.dart';
import 'geolocator_location_provider.dart';

void main() {
  runApp(const RaspTrialApp());
}

/// Everything this trial app turns on. Detector ids are listed in the same
/// order in detector_results_screen.dart (`trialDetectorIds`).
const trialConfig = RaspLeanConfig(
  // Original 4
  screenshotProtection: true,
  usbDetection: true,
  adbDetection: true,
  clipboardProtection: true,
  clipboardAutoClear: true,
  // Device integrity
  rootDetection: true,
  emulatorDetection: true,
  deviceBindingCheck: true,
  cloneDetection: true,
  developerModeDetection: true,
  deviceLockCheck: true,
  secureHardwareCheck: true,
  deviceFingerprintCheck: true,
  // Runtime protection
  fridaDetection: true,
  debuggerDetection: true,
  reverseEngineeringToolsDetection: true,
  hookDetection: true,
  riskyAppDetection: true,
  // App integrity — repackagingDetection deliberately left off: it
  // needs expectedSigningCertSha256, which this demo has no real
  // value for. Supply one to turn it on.
  tamperDetection: true,
  untrustedInstallSourceDetection: true,
  // Network security — highRiskIpDetection calls a third-party API
  // (ipapi.co) directly and always reports unavailable in debug
  // builds (that service's own deliberate choice) — left on so you
  // can see that honest behavior rather than hiding it.
  vpnDetection: true,
  mitmDetection: true,
  highRiskIpDetection: true,
  // Privacy & screen
  overlayDetection: true,
  accessibilityDetection: true,
  externalDisplayDetection: true,
  // Newer detectors (Tasks 3a-3c). Those needing a runtime permission
  // (READ_PHONE_STATE, location) report UNAVAILABLE until it is granted in
  // Settings; malware_reputation reports UNAVAILABLE without a signed list.
  mockLocationDetection: true,
  timeSpoofingDetection: true,
  unsafeWifiDetection: true,
  screenRecordingDetection: true,
  vishingCallDetection: true,
  simChangeDetection: true,
  thirdPartyKeyboardDetection: true,
  taskHijackDetection: true,
  deviceStateAttestationDetection: true,
  malwareReputationDetection: true,
  // Evidence envelopes (device-key signed) instead of legacy HMAC batches;
  // the first delivery registers this device with the backend.
  useEvidenceEnvelope: true,
);

class RaspTrialApp extends StatelessWidget {
  const RaspTrialApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RASP Shield — Lean Trial',
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF0B5FFF),
        useMaterial3: true,
      ),
      home: const SecurityDashboard(),
    );
  }
}

/// Three-state badge for every `bool?` this SDK returns — never collapses
/// `null` into "safe". Matches the SDK's own true/false/null contract.
enum TriState { yes, no, unknown }

TriState triFrom(bool? value) =>
    value == null ? TriState.unknown : (value ? TriState.yes : TriState.no);

class SecurityDashboard extends StatefulWidget {
  const SecurityDashboard({super.key});

  @override
  State<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends State<SecurityDashboard>
    with WidgetsBindingObserver {
  // ── Integration status ──────────────────────────────────────────────────
  RaspIntegrationStatus? _integrationStatus;

  // ── The config-driven session — owns polling, change-detection, the
  // heartbeat re-confirmation, and location-on-detection. See
  // package:rasp_shield/sdk/lean_session.dart. This demo enables all 4
  // controls (matching this screen's previous always-on-4 behavior
  // exactly) — flip any of these to `false` to see the "only what you ask
  // for activates" behavior in your own integration.
  RaspLeanSession? _session;
  StreamSubscription<RaspLeanState>? _stateSub;
  RaspLeanState _state = RaspLeanState.initial;

  /// This app's own location refresh — the SDK never fetches location
  /// itself (see RaspLocationSnapshot's doc); this just keeps
  /// `_session.currentLocation` reasonably fresh so a DETECTED event has
  /// somewhere to pull a coordinate from when it ships. A failed/denied
  /// read leaves `currentLocation` at whatever it was before (never
  /// cleared to a guess), so it degrades to "no location on this event"
  /// rather than a stale one being worse than none.
  Timer? _locationTimer;

  /// The previous emission from `stateStream`, so in-app reactions
  /// (SnackBar/warning dialog) fire only on a genuine transition — never
  /// on a repeated poll of an already-known state, and never on this
  /// screen's very first reading (`null` here means "nothing to compare
  /// against yet").
  RaspLeanState? _previousLeanState;

  final _clipboardTestController = TextEditingController();

  // ── Backend sync (RaspSecurityEventShipper) ───────────────────────────────
  //
  // This is the ONLY new piece for talking to your platform backend. Paste
  // the JSON credential the platform's web UI hands you after registering
  // an application, tap "Configure" once, and from then on this screen
  // ships every state change automatically — you don't call anything
  // per-event, the same way adding Firebase Analytics doesn't make you log
  // every screen view by hand once it's initialized. Persisted securely
  // (see RaspSecurityEventShipper.configureAndPersist) — no longer lost on
  // restart.
  final _credentialController = TextEditingController();
  bool _shipperConfigured = false;
  String? _lastShipError;
  DateTime? _lastSyncAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // Fires on any failed delivery (bad network, backend down, rejected
    // signature) — never thrown, always routed here instead. Purely
    // informational for this demo screen; a real app might log this to
    // its own crash-reporting pipeline instead of a banner.
    RaspSecurityEventShipper.onShipError = (reason) {
      if (mounted) setState(() => _lastShipError = reason);
    };
    _bootstrap();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateSub?.cancel();
    _locationTimer?.cancel();
    _session?.dispose(); // also turns clipboard protection back off
    _clipboardTestController.dispose();
    _credentialController.dispose();
    RaspSecurityEventShipper.onShipError = null;
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Re-check on resume — Developer Options / a cable can change while
    // the app was backgrounded; a stale cached value is a false sense of
    // security on a banking screen.
    if (state == AppLifecycleState.resumed) {
      _session?.refreshNow();
    }
  }

  Future<void> _bootstrap() async {
    // Step 1 — ALWAYS verify integration first. See the integration guide's
    // Part C: this is what catches a plugin that silently never registered
    // (stale pub get, ProGuard-stripped release build, etc.) instead of
    // every method below quietly returning null forever.
    final status = await RaspSecurityControls.verifyIntegration();
    setState(() => _integrationStatus = status);

    if (status == RaspIntegrationStatus.pluginNotRegistered) {
      // Fail loud. In a real banking app this should block sensitive
      // screens and alert your monitoring pipeline, not just show a banner.
      return;
    }

    // Recover a credential configured in a previous run, if any — see
    // RaspSecurityEventShipper.configureAndPersist for where it was saved.
    final restored = await RaspSecurityEventShipper.restore();
    if (restored && mounted) setState(() => _shipperConfigured = true);

    final session = await RaspLeanSession.start(trialConfig);
    _stateSub = session.stateStream.listen((state) {
      if (mounted) setState(() => _state = state);
      _reactToStateChange(_previousLeanState, state);
      _previousLeanState = state;
    });
    if (mounted) {
      setState(() {
        _session = session;
        _state = session.current;
        if (_shipperConfigured) _lastSyncAt = DateTime.now();
      });
    }

    // Keep the session's location reasonably fresh — the SDK itself never
    // fetches this, so this app does, on its own schedule. Every 15s is a
    // deliberate middle ground: frequent enough that a DETECTED event
    // rarely ships with no coordinate, without polling GPS continuously.
    unawaited(_refreshLocation());
    _locationTimer = Timer.periodic(const Duration(seconds: 15), (_) => _refreshLocation());
  }

  Future<void> _refreshLocation() async {
    final snapshot = await captureLocationSnapshot();
    // A failed/denied read leaves the session's last-known value alone —
    // see this field's own doc for why that's the honest default rather
    // than clearing to null on a single transient failure.
    if (snapshot != null) _session?.currentLocation = snapshot;
  }

  // ── Screenshot / video ───────────────────────────────────────────────────

  Future<void> _toggleScreenshotProtection(bool enable) async {
    if (enable) {
      await RaspSecurityControls.enableScreenshotProtection();
    } else {
      await RaspSecurityControls.disableScreenshotProtection();
    }
    await _session?.refreshNow();
  }

  // ── Clipboard ────────────────────────────────────────────────────────────

  Future<void> _toggleClipboardProtection(bool enable) async {
    if (enable) {
      await RaspSecurityControls.enableClipboardProtection(autoClearOnCopy: true);
    } else {
      await RaspSecurityControls.disableClipboardProtection();
    }
    await _session?.refreshNow();
  }

  Future<void> _clearClipboardNow() async {
    await RaspSecurityControls.clearClipboard();
    await _session?.refreshNow();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Clipboard wiped.')),
      );
    }
  }

  // ── Backend sync ─────────────────────────────────────────────────────────

  Future<void> _configureShipper() async {
    final ok = await RaspSecurityEventShipper.configureAndPersist(
      _credentialController.text.trim(),
    );
    if (!mounted) return;
    setState(() {
      _shipperConfigured = ok;
      _lastShipError = ok ? null : 'Could not parse that credential JSON.';
    });
    if (ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Configured — syncing will now happen automatically.')),
      );
      await _session?.refreshNow();
      if (mounted) setState(() => _lastSyncAt = DateTime.now());
    }
  }

  // ── In-app reactions ─────────────────────────────────────────────────────
  //
  // Separate from backend shipping: this is what lets the app itself warn
  // the user or take action the instant something changes, instead of only
  // recording it for later. Every check below compares `previous` against
  // `current` and fires only on the specific transition described — never
  // on a repeated poll of a state that was already true, and never on this
  // screen's very first reading (`previous == null`).

  void _reactToStateChange(RaspLeanState? previous, RaspLeanState current) {
    final adbJustEnabled = current.usb.usbDebuggingEnabled == true &&
        previous?.usb.usbDebuggingEnabled != true;
    if (adbJustEnabled) {
      _showThreatAndCloseApp(
        title: 'Developer Mode Detected',
        message: 'USB debugging is enabled on this device. For your '
            'security, please disable Developer Options in Settings.',
      );
      return; // app is closing — skip the lighter checks below
    }

    if (current.usb.usbConnected == true && previous?.usb.usbConnected != true) {
      _showBanner('USB cable/dock connected.');
    }

    if (current.screenshotActive == false && previous?.screenshotActive != false) {
      _showBanner('Screenshot protection is OFF — sensitive screens are exposed.');
    }

    if (current.clipboardEvidence.changeCount > 0) {
      _showBanner('Clipboard activity detected and cleared.');
    }
  }

  void _showBanner(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.orange.shade800),
    );
  }

  /// A dramatic response reserved for the one scenario the user explicitly
  /// asked for: developer mode / USB debugging. Everything else above gets
  /// only [_showBanner] — forcing the app closed on every minor detection
  /// would train the user to ignore the warning entirely.
  void _showThreatAndCloseApp({required String title, required String message}) {
    if (!mounted) return;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => _ThreatCountdownDialog(title: title, message: message, seconds: 5),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('RASP Shield — Lean Trial'),
        actions: [
          IconButton(
            tooltip: 'Detector results',
            icon: const Icon(Icons.list_alt),
            onPressed: _session == null
                ? null
                : () => Navigator.of(context).push(MaterialPageRoute<void>(
                      builder: (_) => DetectorResultsScreen(session: _session!),
                    )),
          ),
        ],
      ),
      body: _integrationStatus == null
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: () async {
                await _session?.refreshNow();
              },
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _IntegrationBanner(status: _integrationStatus!),
                  const SizedBox(height: 16),
                  _BackendSyncCard(
                    configured: _shipperConfigured,
                    controller: _credentialController,
                    lastSyncAt: _lastSyncAt,
                    lastError: _lastShipError,
                    onConfigure: _configureShipper,
                    onSyncNow: () => _session?.refreshNow(),
                  ),
                  const SizedBox(height: 16),
                  _ScreenshotCard(
                    active: _state.screenshotActive,
                    onToggle: _toggleScreenshotProtection,
                  ),
                  const SizedBox(height: 16),
                  _UsbCard(
                    usb: _state.usb,
                    onRefresh: () => _session?.refreshNow(),
                  ),
                  const SizedBox(height: 16),
                  _ClipboardCard(
                    active: _state.clipboardActive,
                    evidence: _state.clipboardEvidence,
                    controller: _clipboardTestController,
                    onToggle: _toggleClipboardProtection,
                    onClearNow: _clearClipboardNow,
                    onRefresh: () => _session?.refreshNow(),
                  ),
                  const SizedBox(height: 16),
                  _ExtendedDetectorsCard(detectors: _state.extendedDetectors),
                ],
              ),
            ),
    );
  }
}

// ── Shared status pill ──────────────────────────────────────────────────────

class _StatusPill extends StatelessWidget {
  final TriState state;
  final String yesLabel;
  final String noLabel;

  const _StatusPill({
    required this.state,
    required this.yesLabel,
    required this.noLabel,
  });

  @override
  Widget build(BuildContext context) {
    final (Color color, IconData icon, String label) = switch (state) {
      TriState.yes => (Colors.red, Icons.warning_amber_rounded, yesLabel),
      TriState.no => (Colors.green, Icons.check_circle, noLabel),
      TriState.unknown => (Colors.grey, Icons.help_outline, 'Unknown'),
    };
    return Chip(
      avatar: Icon(icon, color: Colors.white, size: 18),
      label: Text(label, style: const TextStyle(color: Colors.white)),
      backgroundColor: color,
    );
  }
}

class _SectionCard extends StatelessWidget {
  final String title;
  final IconData icon;
  final List<Widget> children;

  const _SectionCard({
    required this.title,
    required this.icon,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 1,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, color: Theme.of(context).colorScheme.primary),
                const SizedBox(width: 8),
                Text(title, style: Theme.of(context).textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }
}

// ── Integration banner ──────────────────────────────────────────────────────

class _IntegrationBanner extends StatelessWidget {
  final RaspIntegrationStatus status;
  const _IntegrationBanner({required this.status});

  @override
  Widget build(BuildContext context) {
    final (Color color, String text) = switch (status) {
      RaspIntegrationStatus.ok => (
          Colors.green.shade700,
          'Plugin registered — controls below are live.'
        ),
      RaspIntegrationStatus.pluginNotRegistered => (
          Colors.red.shade700,
          'Plugin NOT registered — a real build defect. Every control below '
              'will silently no-op until this is fixed.'
        ),
      RaspIntegrationStatus.unsupportedPlatform => (
          Colors.orange.shade800,
          'Unsupported platform — these 3 controls are Android-only. '
              'Expected on iOS/desktop/web.'
        ),
    };
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color),
      ),
      child: Row(
        children: [
          Icon(Icons.verified_user, color: color),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: TextStyle(color: color))),
        ],
      ),
    );
  }
}

// ── Backend sync card ────────────────────────────────────────────────────────

class _BackendSyncCard extends StatelessWidget {
  final bool configured;
  final TextEditingController controller;
  final DateTime? lastSyncAt;
  final String? lastError;
  final VoidCallback onConfigure;
  final VoidCallback onSyncNow;

  const _BackendSyncCard({
    required this.configured,
    required this.controller,
    required this.lastSyncAt,
    required this.lastError,
    required this.onConfigure,
    required this.onSyncNow,
  });

  @override
  Widget build(BuildContext context) {
    return _SectionCard(
      title: 'Backend Sync',
      icon: Icons.cloud_sync,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Chip(
              avatar: Icon(
                configured ? Icons.check_circle : Icons.help_outline,
                color: Colors.white,
                size: 18,
              ),
              label: Text(
                configured ? 'Configured' : 'Not configured',
                style: const TextStyle(color: Colors.white),
              ),
              backgroundColor: configured ? Colors.green : Colors.grey,
            ),
            if (configured)
              TextButton.icon(
                onPressed: onSyncNow,
                icon: const Icon(Icons.sync),
                label: const Text('Sync now'),
              ),
          ],
        ),
        const SizedBox(height: 12),
        if (!configured) ...[
          const Text(
            'Paste the JSON credential downloaded from the RASP Shield '
            'platform (Applications → your app → download credential). '
            'Configure once — after that, every state change on this '
            'screen ships automatically, no further calls needed. Saved '
            'to encrypted on-device storage, so you will not need to '
            'paste it again after restarting the app.',
            style: TextStyle(fontSize: 12, color: Colors.black54),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: controller,
            maxLines: 4,
            decoration: const InputDecoration(
              labelText: 'Credential JSON',
              hintText: '{ "organization_id": "...", "api_key": "...", ... }',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              onPressed: onConfigure,
              icon: const Icon(Icons.link),
              label: const Text('Configure'),
            ),
          ),
        ] else ...[
          Text(
            lastSyncAt == null
                ? 'Configured — waiting for the next state change to sync.'
                : 'Last synced: $lastSyncAt',
            style: const TextStyle(fontSize: 12, color: Colors.black54),
          ),
        ],
        if (lastError != null) ...[
          const SizedBox(height: 8),
          Text(
            'Last error: $lastError',
            style: const TextStyle(fontSize: 12, color: Colors.red),
          ),
        ],
      ],
    );
  }
}

// ── Screenshot / video card ─────────────────────────────────────────────────

class _ScreenshotCard extends StatelessWidget {
  final bool? active;
  final ValueChanged<bool> onToggle;

  const _ScreenshotCard({required this.active, required this.onToggle});

  @override
  Widget build(BuildContext context) {
    return _SectionCard(
      title: 'Screenshot & Video Block',
      icon: Icons.screenshot_monitor,
      children: [
        const Text(
          'FLAG_SECURE blocks BOTH still screenshots and screen recording/'
          'casting with one control — there is no separate video toggle.',
          style: TextStyle(fontSize: 13, color: Colors.black54),
        ),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            _StatusPill(
              state: triFrom(active),
              yesLabel: 'Blocked',
              noLabel: 'Not blocked',
            ),
            Switch(
              value: active ?? false,
              onChanged: onToggle,
            ),
          ],
        ),
        const SizedBox(height: 4),
        const Text(
          'Try it: take a screenshot or start a screen recording right now '
          '— it should fail / show black while this is ON.',
          style: TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
        ),
      ],
    );
  }
}

// ── USB / ADB card ──────────────────────────────────────────────────────────

class _UsbCard extends StatelessWidget {
  final RaspUsbState usb;
  final VoidCallback onRefresh;

  const _UsbCard({required this.usb, required this.onRefresh});

  @override
  Widget build(BuildContext context) {
    return _SectionCard(
      title: 'USB & USB Debugging',
      icon: Icons.usb,
      children: [
        Row(
          children: [
            const Expanded(child: Text('USB cable / dock connected')),
            _StatusPill(
              state: triFrom(usb.usbConnected),
              yesLabel: 'Connected',
              noLabel: 'Not connected',
            ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            const Expanded(child: Text('USB debugging (ADB) enabled')),
            _StatusPill(
              state: triFrom(usb.usbDebuggingEnabled),
              yesLabel: 'ADB ON',
              noLabel: 'ADB off',
            ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            const Expanded(child: Text('Developer options unlocked')),
            _StatusPill(
              state: triFrom(usb.developerModeEnabled),
              yesLabel: 'Unlocked',
              noLabel: 'Locked',
            ),
          ],
        ),
        const SizedBox(height: 8),
        Text('Connected USB device count: ${usb.connectedDeviceCount}',
            style: const TextStyle(fontSize: 13)),
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerRight,
          child: TextButton.icon(
            onPressed: onRefresh,
            icon: const Icon(Icons.refresh),
            label: const Text('Refresh now'),
          ),
        ),
        const Text(
          'Auto-refreshes every 4s and on app resume. Detection only — '
          'Android has no API to block ADB/USB; decide your own policy '
          '(e.g. step-up auth, block transaction) when these fire.',
          style: TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
        ),
      ],
    );
  }
}

// ── Clipboard card ───────────────────────────────────────────────────────────

class _ClipboardCard extends StatelessWidget {
  final bool? active;
  final RaspClipboardEvidence evidence;
  final TextEditingController controller;
  final ValueChanged<bool> onToggle;
  final VoidCallback onClearNow;
  final VoidCallback onRefresh;

  const _ClipboardCard({
    required this.active,
    required this.evidence,
    required this.controller,
    required this.onToggle,
    required this.onClearNow,
    required this.onRefresh,
  });

  @override
  Widget build(BuildContext context) {
    return _SectionCard(
      title: 'Clipboard Protection',
      icon: Icons.content_paste_off,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            _StatusPill(
              state: triFrom(active),
              yesLabel: 'Guarding',
              noLabel: 'Off',
            ),
            Switch(value: active ?? false, onChanged: onToggle),
          ],
        ),
        const SizedBox(height: 12),
        TextField(
          controller: controller,
          decoration: const InputDecoration(
            labelText: 'Test text — select it and tap Copy',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          children: [
            OutlinedButton.icon(
              onPressed: onClearNow,
              icon: const Icon(Icons.cleaning_services),
              label: const Text('Clear clipboard now'),
            ),
            OutlinedButton.icon(
              onPressed: onRefresh,
              icon: const Icon(Icons.refresh),
              label: const Text('Refresh evidence'),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Text(
          'Copies observed since last read: ${evidence.changeCount}   '
          '${evidence.lastChangeAt != null ? "· last at ${evidence.lastChangeAt}" : ""}',
          style: const TextStyle(fontSize: 12, color: Colors.black54),
        ),
        const Text(
          'With guarding ON: copy the text above, then try pasting anywhere '
          '— it should paste empty. Never reads the actual clipboard '
          'content, only that a change happened.',
          style: TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
        ),
      ],
    );
  }
}

// ── Threat countdown dialog ──────────────────────────────────────────────────
//
// A plain Timer.periodic must NOT live inside a StatefulBuilder's `builder`
// — that callback re-runs on every rebuild, which would restart the timer
// each second instead of ticking it down. A dedicated StatefulWidget that
// owns the timer in initState/dispose is the correct pattern.

class _ThreatCountdownDialog extends StatefulWidget {
  final String title;
  final String message;
  final int seconds;

  const _ThreatCountdownDialog({
    required this.title,
    required this.message,
    this.seconds = 5,
  });

  @override
  State<_ThreatCountdownDialog> createState() => _ThreatCountdownDialogState();
}

class _ThreatCountdownDialogState extends State<_ThreatCountdownDialog> {
  late int _secondsLeft = widget.seconds;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
      setState(() => _secondsLeft--);
      if (_secondsLeft <= 0) {
        timer.cancel();
        // The standard, idiomatic Flutter way an app closes itself — the
        // same mechanism a real banking app's "force logout and exit"
        // flow would use. Android deliberately gives no app a way to
        // guarantee its own full process kill; this backgrounds/exits the
        // app the same way the system back button from the root screen
        // would, which is the closest a client-side call can get.
        SystemNavigator.pop();
      }
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      icon: const Icon(Icons.warning_amber_rounded, color: Colors.red, size: 40),
      title: Text(widget.title),
      content: Text(
        '${widget.message}\n\nClosing this app in $_secondsLeft '
        'second${_secondsLeft == 1 ? '' : 's'}.',
      ),
    );
  }
}

// ── Extended detectors card ─────────────────────────────────────────────────
//
// Everything beyond the original 4 lean controls — real values from
// `RaspLeanSession`'s `extendedDetectors` map, grouped by category the way
// a real dashboard would show them. Nothing here is placeholder data: an
// entry only appears once its detector has actually returned a result.

class _ExtendedDetectorsCard extends StatelessWidget {
  final Map<String, DetectionResult> detectors;

  const _ExtendedDetectorsCard({required this.detectors});

  @override
  Widget build(BuildContext context) {
    if (detectors.isEmpty) return const SizedBox.shrink();

    final byCategory = <String, List<DetectionResult>>{};
    for (final result in detectors.values) {
      byCategory.putIfAbsent(result.category.name, () => []).add(result);
    }
    final threatCount = detectors.values.where((r) => r.status.isThreat).length;

    return _SectionCard(
      title: 'Extended Detectors (${detectors.length})',
      icon: Icons.shield_outlined,
      children: [
        Text(
          threatCount > 0
              ? '$threatCount finding${threatCount == 1 ? '' : 's'} detected'
              : 'No findings — every enabled detector reports secure or unavailable.',
          style: TextStyle(
            color: threatCount > 0 ? Colors.red : Colors.black54,
            fontWeight: threatCount > 0 ? FontWeight.bold : FontWeight.normal,
            fontSize: 13,
          ),
        ),
        for (final entry in byCategory.entries) ...[
          Padding(
            padding: const EdgeInsets.only(top: 12, bottom: 4),
            child: Text(
              _categoryLabel(entry.key),
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
            ),
          ),
          for (final result in entry.value) _ExtendedDetectorRow(result: result),
        ],
      ],
    );
  }

  /// `ThreatCategory` enum names are camelCase (e.g. `deviceIntegrity`) —
  /// split into words and capitalize for display.
  String _categoryLabel(String raw) {
    final spaced = raw.replaceAllMapped(
      RegExp(r'([a-z0-9])([A-Z])'),
      (m) => '${m[1]} ${m[2]}',
    );
    return spaced.isEmpty ? spaced : spaced[0].toUpperCase() + spaced.substring(1);
  }
}

class _ExtendedDetectorRow extends StatelessWidget {
  final DetectionResult result;

  const _ExtendedDetectorRow({required this.result});

  @override
  Widget build(BuildContext context) {
    final threat = result.status.isThreat;
    final (Color color, IconData icon, String label) = switch (result.status) {
      DetectionStatus.detected => (Colors.red, Icons.warning_amber_rounded, 'Detected'),
      DetectionStatus.secure => (Colors.green, Icons.check_circle, 'Secure'),
      DetectionStatus.unavailable => (Colors.grey, Icons.help_outline, 'Unavailable'),
      DetectionStatus.unknown => (Colors.orange, Icons.question_mark, 'Unknown'),
      DetectionStatus.error => (Colors.orange, Icons.error_outline, 'Error'),
    };
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 16),
          const SizedBox(width: 6),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  result.title,
                  style: TextStyle(
                    fontWeight: threat ? FontWeight.bold : FontWeight.normal,
                    fontSize: 13,
                  ),
                ),
                if (result.unavailableReason != null)
                  Text(
                    result.unavailableReason!,
                    style: const TextStyle(fontSize: 11, color: Colors.black45),
                  ),
              ],
            ),
          ),
          Text(label, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
        ],
      ),
    );
  }
}
