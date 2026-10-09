import 'dart:async';

import 'package:flutter/foundation.dart' show kDebugMode, visibleForTesting;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show SystemNavigator, rootBundle;
import 'package:permission_handler/permission_handler.dart';
import 'package:rasp_shield/sdk/core/core.dart'
    show DetectionResult, DetectionStatus, DetectionStatusX;
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';
import 'package:rasp_shield/sdk/lean_session.dart';
import 'package:rasp_shield/sdk/security_controls.dart';

import 'detector_catalog.dart';
import 'backend_check.dart';
import 'build_config.dart';
import 'debug_result_logger.dart';
import 'detector_results_screen.dart';
import 'fraud_risk_screen.dart';
import 'geolocator_location_provider.dart';
import 'permission_onboarding.dart';
import 'test_reputation_list.dart';
import 'threat_policy.dart';
import 'trial_tools.dart';

void main() {
  runApp(const RaspTrialApp());
}

/// Requests READ_PHONE_STATE at runtime (permission_handler's
/// `Permission.phone` asks only for the phone permissions the manifest
/// declares — here just READ_PHONE_STATE). Replaceable in tests.
@visibleForTesting
Future<PermissionStatus> Function() requestPhonePermission = () => Permission.phone.request();

/// Asks for location (permission_handler `Permission.locationWhenInUse`:
/// coarse + fine, as declared). Called when the user turns "Share location"
/// on. Replaceable in tests.
@visibleForTesting
Future<PermissionStatus> Function() requestLocationPermission = () => Permission.locationWhenInUse.request();

/// Reads one opted-in fix (geolocator, with the platform mock flag).
/// Replaceable in tests.
@visibleForTesting
Future<RaspLocationSnapshot?> Function() readLocationFix = () => captureLocationSnapshot(shareWithBackend: true);

/// Current READ_PHONE_STATE status, without asking. Replaceable in tests.
@visibleForTesting
Future<PermissionStatus> Function() phonePermissionStatus = () => Permission.phone.status;

/// Everything this trial app turns on. Detector ids are listed in the same
/// order in detector_catalog.dart (`trialDetectorIds`). [pinHost] and [pins]
/// set the `mitm` SPKI pin (the "Trial checks" card); none by default.
/// [expectedSigningCertSha256] comes from the build (TrialBuildConfig).
/// [useTestReputationList]: the signed test list that names Chrome ("Trial
/// checks" card) instead of the list from the backend.
RaspLeanConfig trialConfig({
  String? pinHost,
  List<String> pins = const [],
  String? expectedSigningCertSha256,
  bool useTestReputationList = false,
}) => RaspLeanConfig(
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
  // App integrity — tamper compares the signing certificate with the hash
  // the Android build wrote to assets/generated/rasp_build.json (Task 6.0);
  // without it tamper reports UNKNOWN "not configured". repackagingDetection
  // stays off (tamper covers the certificate check).
  tamperDetection: true,
  expectedSigningCertSha256: expectedSigningCertSha256,
  untrustedInstallSourceDetection: true,
  // Network security — highRiskIpDetection asks the platform backend's
  // GET /v1/ip-risk (HMAC-signed with the credential pasted in "Backend
  // Sync"); UNAVAILABLE until a credential is configured.
  vpnDetection: true,
  mitmDetection: true,
  certificatePinHost: pinHost,
  certificatePins: pins,
  highRiskIpDetection: true,
  // Privacy & screen
  overlayDetection: true,
  accessibilityDetection: true,
  externalDisplayDetection: true,
  // Newer detectors (Tasks 3a-3c). sim_change and vishing_call need
  // READ_PHONE_STATE ("Grant permissions" in the Trial checks card);
  // mock_location needs location (granted in Settings). malware_reputation
  // uses the backend's signed list (key from the credential), or, with the
  // switch in the Trial checks card, the test list in
  // lib/test_reputation_list.dart.
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
  malwareReputationListJson: useTestReputationList ? testReputationListJson : null,
  malwareReputationPublicKey: useTestReputationList ? testReputationPublicKey : null,
  malwareReputationAutoUpdate: !useTestReputationList,
  // Evidence envelopes (device-key signed) instead of legacy HMAC batches;
  // the first delivery registers this device with the backend.
  useEvidenceEnvelope: true,
  // Task 8.1 fraud signals and the session risk / transaction API (the
  // "Fraud risk" screen). The id-hash salt comes from the pasted credential
  // (account_hash_salt); without it login/transaction report UNAVAILABLE.
  remoteControlAppDetection: true,
  screenSharingDetection: true,
  otpInterceptionDetection: true,
  smsReaderAbuseDetection: true,
  otpForwardingDetection: true,
  sessionRiskScoring: true,
);

class RaspTrialApp extends StatelessWidget {
  const RaspTrialApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RASP Shield — Lean Trial',
      debugShowCheckedModeBanner: false,
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

  /// Location is read only while the user has "Share location" on (opt-in,
  /// off by default, not saved): then a fix every 15 s goes to the SDK
  /// (mock_location) and with events to the backend (location_opt_in).
  Timer? _locationTimer;
  bool _shareLocation = false;
  RaspLocationSnapshot? _lastFix;

  /// From the Android build (signing certificate hash for tamper).
  TrialBuildConfig _buildConfig = TrialBuildConfig.none;

  /// The previous emission from `stateStream`, so in-app reactions
  /// (SnackBar/warning dialog) fire only on a genuine transition — never
  /// on a repeated poll of an already-known state, and never on this
  /// screen's very first reading (`null` here means "nothing to compare
  /// against yet").
  RaspLeanState? _previousLeanState;

  final _clipboardTestController = TextEditingController();

  /// Trial setting, off by default: close the app (after a 5 s countdown)
  /// when USB debugging turns on. When off, developer options / ADB / USB
  /// only show the warning banner. Not persisted — off again on restart.
  bool _closeOnUsbDebugging = false;

  /// Debug builds only: every detector result to logcat (tag RASP_RESULT).
  /// `kDebugMode` is a compile-time constant, so release builds drop it.
  final DebugResultLogger? _resultLogger = kDebugMode ? DebugResultLogger() : null;

  // ── Trial checks card ────────────────────────────────────────────────────
  PermissionStatus? _phonePermission;
  /// sim_change / vishing_call verdicts read right after the permission answer.
  String? _phoneRecheck;
  /// The mitm SPKI pin the session runs with (none by default; not persisted).
  String? _pinHost;
  List<String> _pins = const [];
  bool _useTestReputationList = false;
  final _pinHostController = TextEditingController();
  final _pinController = TextEditingController();

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
  /// Showing the paste field again to replace a configured credential.
  bool _replacingCredential = false;
  String? _connectionResult;
  bool _checkingConnection = false;
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
    _pinHostController.dispose();
    _pinController.dispose();
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

    unawaited(phonePermissionStatus().then((status) {
      if (mounted) setState(() => _phonePermission = status);
    }));
    _buildConfig = await TrialBuildConfig.load(rootBundle);
    await _startSession(_config());
    if (mounted && _shipperConfigured) setState(() => _lastSyncAt = DateTime.now());
    await _maybeShowPermissionIntro();
  }

  /// First launch only: explains Phone state and (optional) Location, then
  /// asks for Phone state on Continue. Location is never asked here — only
  /// when "Share location" is switched on. The answer is stored, so this
  /// shows once per install (if storage fails it shows again next launch).
  Future<void> _maybeShowPermissionIntro() async {
    String? answer;
    try {
      answer = await readPermissionIntroAnswer();
    } catch (_) {
      answer = null;
    }
    if (answer != null || !mounted) return;
    final proceed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const PermissionIntroDialog(),
    );
    try {
      await savePermissionIntroAnswer(proceed == true ? 'continue' : 'not_now');
    } catch (_) {
      // Not remembered; the explanation shows again next launch.
    }
    if (proceed == true && mounted) await _grantPhonePermission();
  }

  RaspLeanConfig _config() => trialConfig(
        pinHost: _pinHost,
        pins: _pins,
        expectedSigningCertSha256: _buildConfig.expectedSigningCertSha256,
        useTestReputationList: _useTestReputationList,
      );

  Future<void> _setTestReputationList(bool on) async {
    setState(() => _useTestReputationList = on);
    await _restartSession();
  }

  Future<void> _startSession(RaspLeanConfig config) async {
    final session = await RaspLeanSession.start(config);
    _stateSub = session.stateStream.listen((state) {
      _resultLogger?.log(state);
      if (mounted) setState(() => _state = state);
      _reactToStateChange(_previousLeanState, state);
      _previousLeanState = state;
    });
    if (mounted) {
      setState(() {
        _session = session;
        _state = session.current;
      });
    }
  }

  bool _restarting = false;

  /// Stops the session and starts it again with the current pin settings.
  /// Never hangs: dispose and start each wait at most 2 s for the native side
  /// (RaspLeanSession.nativeCallTimeout), then continue. A failure is shown
  /// instead of leaving the screen without a session; a second tap while a
  /// restart runs is ignored.
  Future<void> _restartSession() async {
    if (_restarting) return;
    _restarting = true;
    try {
      final old = _session;
      // Not awaited: the subscription stops at once; its future only reports
      // clean-up (and, completed in the root zone, never resolves inside a
      // widget test's fake async).
      final sub = _stateSub;
      _stateSub = null;
      if (sub != null) unawaited(sub.cancel());
      if (mounted) setState(() => _session = null);
      await old?.dispose().timeout(RaspLeanSession.nativeCallTimeout, onTimeout: () {});
      await _startSession(_config());
      if (_shareLocation && _lastFix != null) _session?.currentLocation = _lastFix;
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Could not restart the session: $e')));
      }
    } finally {
      _restarting = false;
    }
  }

  // ── Trial checks ─────────────────────────────────────────────────────────

  /// Asks for READ_PHONE_STATE, then re-runs the detectors (one session tick
  /// includes sim_change and vishing_call) and shows their new verdicts.
  Future<void> _grantPhonePermission() async {
    final status = await requestPhonePermission();
    if (!mounted) return;
    setState(() {
      _phonePermission = status;
      _phoneRecheck = 'Re-running the SIM and call checks…';
    });
    if (isRefused(status)) {
      unawaited(showPermissionRefusedDialog(
        context,
        what: 'Phone state',
        status: status,
        effect: 'SIM change and Call during app use stay UNAVAILABLE.',
      ));
    }
    final session = _session;
    if (session == null) return;
    // Wait for a SIM result observed after the answer — a tick that was
    // already running may still report the old (no-permission) result.
    final answeredAt = DateTime.now();
    final next = session.stateStream
        .firstWhere((s) => s.extendedDetectors['sim_change']?.observedAt.isBefore(answeredAt) == false)
        .timeout(const Duration(seconds: 15), onTimeout: () => session.current);
    await session.refreshNow();
    final state = await next;
    if (!mounted) return;
    setState(() => _phoneRecheck =
        'SIM change: ${detectorVerdict(state, 'sim_change')}\n'
        'Call during app use: ${detectorVerdict(state, 'vishing_call')}');
  }

  Future<void> _resetSimBaseline() async {
    final ok = await RaspLeanSession.resetSimBaseline();
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(ok
          ? 'SIM baseline cleared. The next check stores a new one (UNKNOWN "baseline stored").'
          : 'SIM baseline not reset (only allowed in a debug build).'),
    ));
    await _session?.refreshNow();
  }

  Future<void> _applyPin() async {
    final host = _pinHostController.text.trim();
    final pins = parsePins(_pinController.text);
    if (host.isEmpty || pins.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a host and at least one pin.')),
      );
      return;
    }
    setState(() {
      _pinHost = host;
      _pins = pins;
    });
    await _restartSession();
  }

  Future<void> _clearPin() async {
    setState(() {
      _pinHost = null;
      _pins = const [];
    });
    await _restartSession();
  }

  /// The "Share location" switch. On: asks for location, then reads a fix
  /// now and every 15 s. Off (or permission refused): stops reading and
  /// clears the location in the SDK, so nothing more is checked or shipped.
  Future<void> _setShareLocation(bool on) async {
    if (!on) {
      _locationTimer?.cancel();
      _locationTimer = null;
      setState(() {
        _shareLocation = false;
        _lastFix = null;
      });
      _session?.currentLocation = null;
      return;
    }
    final status = await requestLocationPermission();
    if (!mounted) return;
    if (!status.isGranted && !status.isLimited) {
      await showPermissionRefusedDialog(
        context,
        what: 'Location',
        status: status,
        effect: 'Location permission not granted, so location is not shared.',
      );
      return;
    }
    setState(() => _shareLocation = true);
    await _refreshLocation();
    _locationTimer?.cancel();
    _locationTimer = Timer.periodic(const Duration(seconds: 15), (_) => _refreshLocation());
  }

  Future<void> _refreshLocation() async {
    if (!_shareLocation) return;
    final snapshot = await readLocationFix();
    // A failed read keeps the last fix; the SDK reports it stale after 2 min.
    if (snapshot == null || !_shareLocation || !mounted) return;
    _session?.currentLocation = snapshot;
    setState(() => _lastFix = snapshot);
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

  /// Calls the configured backend's /healthz and shows whether this phone
  /// can reach it (with the adb reverse hint for a localhost credential).
  Future<void> _checkConnection() async {
    final origin = RaspSecurityEventShipper.configuredBackendOrigin;
    if (origin == null) {
      setState(() => _connectionResult = 'No backend configured yet: paste a credential first.');
      return;
    }
    setState(() {
      _checkingConnection = true;
      _connectionResult = null;
    });
    final result = await checkBackendConnection(origin);
    if (!mounted) return;
    setState(() {
      _checkingConnection = false;
      _connectionResult = result;
    });
  }

  Future<void> _configureShipper() async {
    final ok = await RaspSecurityEventShipper.configureAndPersist(
      _credentialController.text.trim(),
    );
    if (!mounted) return;
    setState(() {
      _shipperConfigured = ok;
      _connectionResult = null;
      if (ok) _replacingCredential = false;
      _lastShipError = ok ? null : 'Could not parse that credential JSON.';
    });
    if (ok) _credentialController.clear();
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
    // Developer options, USB debugging and USB connection are shown in the
    // persistent warning banner (postureWarnings). Closing the app happens
    // only when the trial setting is switched on.
    if (shouldCloseApp(previous: previous, current: current, closeOnUsbDebugging: _closeOnUsbDebugging)) {
      _showThreatAndCloseApp(
        title: 'Developer Mode Detected',
        message: 'USB debugging is enabled on this device. For your '
            'security, please disable Developer Options in Settings.',
      );
      return; // app is closing — skip the lighter checks below
    }

    if (current.usb.usbDebuggingEnabled == true && previous != null &&
        previous.usb.usbDebuggingEnabled != true) {
      _showBanner('USB debugging (ADB) was turned on.');
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

  /// Closes the app after a countdown. Used only when the "close the app
  /// when USB debugging turns on" trial setting is on (off by default);
  /// otherwise developer mode / ADB / USB only produce warnings.
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
    final warnings = postureWarnings(_state);
    return Scaffold(
      appBar: AppBar(
        title: const Text('RASP Shield — Lean Trial'),
        actions: [
          IconButton(
            tooltip: 'Fraud risk',
            icon: const Icon(Icons.payments_outlined),
            onPressed: _session == null
                ? null
                : () => Navigator.of(context).push(MaterialPageRoute<void>(
                      builder: (_) => FraudRiskScreen(session: _session!),
                    )),
          ),
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
                  if (warnings.isNotEmpty) ...[
                    const SizedBox(height: 12),
                    _PostureWarningBanner(warnings: warnings),
                  ],
                  const SizedBox(height: 16),
                  _BackendSyncCard(
                    configured: _shipperConfigured,
                    controller: _credentialController,
                    lastSyncAt: _lastSyncAt,
                    lastError: _lastShipError,
                    onConfigure: _configureShipper,
                    onSyncNow: () => _session?.refreshNow(),
                    backendHost: RaspSecurityEventShipper.configuredBackendHost,
                    connectionResult: _connectionResult,
                    checkingConnection: _checkingConnection,
                    onCheckConnection: _checkConnection,
                    replacing: _replacingCredential,
                    onReplace: () => setState(() => _replacingCredential = !_replacingCredential),
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
                    closeOnUsbDebugging: _closeOnUsbDebugging,
                    onCloseOnUsbDebuggingChanged: (value) =>
                        setState(() => _closeOnUsbDebugging = value),
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
                  _TrialChecksCard(
                    state: _state,
                    phonePermission: _phonePermission,
                    phoneRecheck: _phoneRecheck,
                    onGrantPhonePermission: _grantPhonePermission,
                    onResetSimBaseline: _resetSimBaseline,
                    pinHost: _pinHost,
                    pins: _pins,
                    pinHostController: _pinHostController,
                    pinController: _pinController,
                    onApplyPin: _applyPin,
                    onClearPin: _clearPin,
                    shareLocation: _shareLocation,
                    lastFix: _lastFix,
                    onShareLocationChanged: _setShareLocation,
                    useTestReputationList: _useTestReputationList,
                    onTestReputationListChanged: _setTestReputationList,
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

  /// `true` for a protection that is on when "yes" (e.g. clipboard
  /// guarding): yes shows green, no shows neutral grey. Default: yes is a
  /// finding (red), no is fine (green).
  final bool yesIsGood;

  const _StatusPill({
    required this.state,
    required this.yesLabel,
    required this.noLabel,
    this.yesIsGood = false,
  });

  @override
  Widget build(BuildContext context) {
    final (Color color, IconData icon, String label) = switch (state) {
      TriState.yes when yesIsGood => (Colors.green, Icons.check_circle, yesLabel),
      TriState.no when yesIsGood => (Colors.grey, Icons.remove_circle_outline, noLabel),
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

// ── Device posture warning banner ────────────────────────────────────────────
//
// Shown while developer options, USB debugging or a USB connection is
// detected. A warning only — the app keeps running (see threat_policy.dart).

class _PostureWarningBanner extends StatelessWidget {
  final List<String> warnings;
  const _PostureWarningBanner({required this.warnings});

  @override
  Widget build(BuildContext context) {
    final color = Colors.orange.shade800;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.warning_amber_rounded, color: color),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Device warning', style: TextStyle(color: color, fontWeight: FontWeight.bold)),
                for (final warning in warnings) Text(warning, style: TextStyle(color: color)),
                const SizedBox(height: 4),
                Text(
                  'The app keeps running. Turn these off in Settings (or unplug USB) to clear this warning.',
                  style: TextStyle(color: color, fontSize: 12),
                ),
              ],
            ),
          ),
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
  /// host[:port] events go to (from the credential; never the key or secret).
  final String? backendHost;
  final bool replacing;
  final VoidCallback onReplace;
  /// Result of the last "Check connection", or null.
  final String? connectionResult;
  final bool checkingConnection;
  final VoidCallback onCheckConnection;

  const _BackendSyncCard({
    required this.configured,
    required this.controller,
    required this.lastSyncAt,
    required this.lastError,
    required this.onConfigure,
    required this.onSyncNow,
    required this.backendHost,
    required this.replacing,
    required this.onReplace,
    required this.connectionResult,
    required this.checkingConnection,
    required this.onCheckConnection,
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
        if (configured) ...[
          Text('Sending to: ${backendHost ?? "unknown"}', key: const Key('backend-host'),
              style: const TextStyle(fontWeight: FontWeight.w600)),
          const Text(
            'Events go to the backend that issued the pasted credential. If this is not your '
            'backend, paste a credential from your own dashboard.',
            style: TextStyle(fontSize: 12, color: Colors.black54),
          ),
          Wrap(spacing: 8, children: [
            TextButton(
              key: const Key('replace-credential'),
              onPressed: onReplace,
              child: Text(replacing ? 'Cancel' : 'Change credential'),
            ),
            TextButton.icon(
              key: const Key('check-connection'),
              onPressed: checkingConnection ? null : onCheckConnection,
              icon: const Icon(Icons.network_check, size: 18),
              label: Text(checkingConnection ? 'Checking…' : 'Check connection'),
            ),
          ]),
          if (connectionResult != null)
            Text(connectionResult!, key: const Key('connection-result'), style: const TextStyle(fontSize: 12)),
          const SizedBox(height: 4),
        ],
        if (!configured || replacing) ...[
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
  final bool closeOnUsbDebugging;
  final ValueChanged<bool> onCloseOnUsbDebuggingChanged;

  const _UsbCard({
    required this.usb,
    required this.onRefresh,
    required this.closeOnUsbDebugging,
    required this.onCloseOnUsbDebuggingChanged,
  });

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
        const SizedBox(height: 8),
        SwitchListTile(
          key: const Key('close-on-usb-debugging'),
          contentPadding: EdgeInsets.zero,
          title: const Text('Close the app when USB debugging turns on'),
          subtitle: const Text(
            'Off by default. When off, developer options, ADB and USB only '
            'show the warning banner. Applies the next time ADB turns on.',
            style: TextStyle(fontSize: 12),
          ),
          value: closeOnUsbDebugging,
          onChanged: onCloseOnUsbDebuggingChanged,
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
              yesIsGood: true,
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

// ── Trial checks card ────────────────────────────────────────────────────────
//
// Controls for trying sim_change, vishing_call, mitm and malware_reputation
// on a phone: the READ_PHONE_STATE request, the debug-only SIM baseline
// reset, the mitm SPKI pin, and the test reputation list's result.

class _TrialChecksCard extends StatelessWidget {
  final RaspLeanState state;
  final PermissionStatus? phonePermission;
  final String? phoneRecheck;
  final VoidCallback onGrantPhonePermission;
  final VoidCallback onResetSimBaseline;
  final String? pinHost;
  final List<String> pins;
  final TextEditingController pinHostController;
  final TextEditingController pinController;
  final VoidCallback onApplyPin;
  final VoidCallback onClearPin;
  final bool shareLocation;
  final RaspLocationSnapshot? lastFix;
  final ValueChanged<bool> onShareLocationChanged;
  final bool useTestReputationList;
  final ValueChanged<bool> onTestReputationListChanged;

  const _TrialChecksCard({
    required this.state,
    required this.phonePermission,
    required this.phoneRecheck,
    required this.onGrantPhonePermission,
    required this.onResetSimBaseline,
    required this.pinHost,
    required this.pins,
    required this.pinHostController,
    required this.pinController,
    required this.onApplyPin,
    required this.onClearPin,
    required this.shareLocation,
    required this.lastFix,
    required this.onShareLocationChanged,
    required this.useTestReputationList,
    required this.onTestReputationListChanged,
  });

  @override
  Widget build(BuildContext context) {
    const hint = TextStyle(fontSize: 12, color: Colors.black54);
    return _SectionCard(
      title: 'Trial checks',
      icon: Icons.science_outlined,
      children: [
        Text('Phone permission (READ_PHONE_STATE): ${phonePermissionLabel(phonePermission)}',
            key: const Key('phone-permission')),
        const Text('Needed by SIM change and Call during app use.', style: hint),
        const SizedBox(height: 8),
        Wrap(spacing: 8, children: [
          FilledButton.icon(
            key: const Key('grant-permissions'),
            onPressed: onGrantPhonePermission,
            icon: const Icon(Icons.phone_android),
            label: const Text('Grant permissions'),
          ),
          if (phonePermission == PermissionStatus.permanentlyDenied)
            TextButton(onPressed: openSettings, child: const Text('Open app settings')),
        ]),
        if (phoneRecheck != null)
          Padding(
            padding: const EdgeInsets.only(top: 6),
            child: Text(phoneRecheck!, key: const Key('phone-recheck'), style: const TextStyle(fontSize: 13)),
          ),
        if (kDebugMode) ...[
          const Divider(height: 24),
          OutlinedButton.icon(
            key: const Key('reset-sim-baseline'),
            onPressed: onResetSimBaseline,
            icon: const Icon(Icons.restart_alt),
            label: const Text('Reset SIM baseline'),
          ),
          const Text(
            'Debug builds only. The next check stores a new baseline and reports UNKNOWN "baseline stored".',
            style: hint,
          ),
        ],
        const Divider(height: 24),
        SwitchListTile(
          key: const Key('share-location'),
          contentPadding: EdgeInsets.zero,
          title: const Text('Share location'),
          subtitle: const Text(
            'Off by default, not saved. When on, the app asks for location, reads a fix '
            'every 15 s for mock_location, sends a location heartbeat every 60 s and '
            'attaches the fix to events (marked location_opt_in). Off clears it on the '
            'phone and on the backend.',
            style: TextStyle(fontSize: 12),
          ),
          value: shareLocation,
          onChanged: onShareLocationChanged,
        ),
        if (shareLocation)
          Text(
            lastFix == null
                ? 'No fix yet.'
                : 'Last fix: '
                    '${lastFix!.latitude.toStringAsFixed(3)}, ${lastFix!.longitude.toStringAsFixed(3)} '
                    '(mock flag: ${lastFix!.isMock ?? "unknown"})',
            key: const Key('last-fix'),
            style: const TextStyle(fontSize: 12),
          ),
        Text(
          locationHeartbeatLabel(state.locationHeartbeat, sharing: shareLocation),
          key: const Key('location-heartbeat'),
          style: const TextStyle(fontSize: 12),
        ),
        Text('Mock location: ${detectorVerdict(state, "mock_location")}', key: const Key('mock-location-result')),
        const Divider(height: 24),
        Text(
          'TLS pin for mitm: ${pinHost == null ? 'none (mitm reports pin_not_configured)' : '$pinHost, ${pins.length} pin(s)'}',
          key: const Key('pin-status'),
        ),
        const SizedBox(height: 8),
        TextField(
          key: const Key('pin-host'),
          controller: pinHostController,
          decoration: const InputDecoration(
            labelText: 'Pinned host', hintText: 'api.example.com', border: OutlineInputBorder(), isDense: true,
          ),
        ),
        const SizedBox(height: 8),
        TextField(
          key: const Key('pin-value'),
          controller: pinController,
          decoration: const InputDecoration(
            labelText: 'SPKI pin(s)', hintText: 'sha256/<Base64 of 32 bytes>, comma-separated', border: OutlineInputBorder(), isDense: true,
          ),
        ),
        Wrap(spacing: 8, children: [
          FilledButton(key: const Key('apply-pin'), onPressed: onApplyPin, child: const Text('Apply pin')),
          TextButton(key: const Key('clear-pin'), onPressed: onClearPin, child: const Text('No pin')),
        ]),
        const Text(
          'A wrong pin makes mitm DETECTED and lists the pins the server really sent (observed_pin) '
          'on the results screen; copy one to get a match.',
          style: hint,
        ),
        const Divider(height: 24),
        SwitchListTile(
          key: const Key('test-reputation-list'),
          contentPadding: EdgeInsets.zero,
          title: Text('Malware reputation: use the test list (flags $testReputationPackage)'),
          value: useTestReputationList,
          onChanged: onTestReputationListChanged,
        ),
        Text('Result: ${detectorVerdict(state, 'malware_reputation')}', key: const Key('reputation-result')),
        Text(
          useTestReputationList
              ? 'A harmless test entry, so you can see DETECTED. To flag another installed app: '
                  'node tool/make_test_reputation_list.js <package>, then rebuild.'
              : 'Off: the signed list from your backend (Backend Sync credential), checked once a day. '
                  'UNAVAILABLE until the backend has a list and the credential carries its key; '
                  'UNKNOWN while the list is empty.',
          key: const Key('reputation-source'),
          style: hint,
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
// `RaspLeanSession`'s `extendedDetectors` map, with the same category
// headings, order and names as the results screen (detector_catalog.dart).
// Nothing here is placeholder data: an entry only appears once its detector
// has actually returned a result.

class _ExtendedDetectorsCard extends StatelessWidget {
  final Map<String, DetectionResult> detectors;

  const _ExtendedDetectorsCard({required this.detectors});

  @override
  Widget build(BuildContext context) {
    if (detectors.isEmpty) return const SizedBox.shrink();

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
        for (final (heading, ids) in groupByCategory(reportedDetectorIds(detectors.keys))) ...[
          Padding(
            padding: const EdgeInsets.only(top: 12, bottom: 4),
            child: Text(
              heading,
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
            ),
          ),
          for (final id in ids) _ExtendedDetectorRow(id: id, result: detectors[id]!),
        ],
      ],
    );
  }
}

class _ExtendedDetectorRow extends StatelessWidget {
  final String id;
  final DetectionResult result;

  const _ExtendedDetectorRow({required this.id, required this.result});

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
                  detectorName(id),
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
