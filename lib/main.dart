import 'dart:async';

import 'package:flutter/foundation.dart' show kDebugMode, visibleForTesting;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData, SystemNavigator, rootBundle;
import 'package:permission_handler/permission_handler.dart';
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';
import 'package:rasp_shield/sdk/lean_session.dart';
import 'package:rasp_shield/sdk/security_controls.dart';

import 'backend_check.dart';
import 'build_config.dart';
import 'debug_result_logger.dart';
import 'detector_results_screen.dart';
import 'feature_catalog.dart';
import 'feature_lab.dart';
import 'feature_lab_screen.dart';
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
/// [enabledFeatures]: the feature ids switched on in the Feature lab
/// (feature_catalog.dart); `null` = [defaultEnabledFeatureIds].
RaspLeanConfig trialConfig({
  String? pinHost,
  List<String> pins = const [],
  String? expectedSigningCertSha256,
  bool useTestReputationList = false,
  Set<String>? enabledFeatures,
}) {
  final features = enabledFeatures ?? defaultEnabledFeatureIds;
  bool on(String id) => features.contains(id);
  return RaspLeanConfig(
    // Original 4
    screenshotProtection: on('screenshot_protection'),
    usbDetection: on('usb_connection'),
    adbDetection: on('adb_enabled'),
    clipboardProtection: on('clipboard_protection'),
    clipboardAutoClear: true,
    // Device integrity
    rootDetection: on('root_jailbreak'),
    emulatorDetection: on('emulator'),
    deviceBindingCheck: on('device_binding'),
    cloneDetection: on('clone'),
    developerModeDetection: on('developer_mode'),
    deviceLockCheck: on('device_lock_missing'),
    secureHardwareCheck: on('secure_hardware_unavailable'),
    deviceFingerprintCheck: on('device_fingerprint'),
    // Runtime protection
    fridaDetection: on('frida'),
    debuggerDetection: on('debugger'),
    reverseEngineeringToolsDetection: on('re_tools'),
    hookDetection: on('hook_detection'),
    riskyAppDetection: on('risky_app'),
    // App integrity — tamper compares the signing certificate with the hash
    // the Android build wrote to assets/generated/rasp_build.json (Task 6.0);
    // without it tamper reports UNKNOWN "not configured". repackage and
    // screenshot_event start off (tamper covers the certificate check) and
    // can be switched on in the Feature lab.
    tamperDetection: on('tamper'),
    expectedSigningCertSha256: expectedSigningCertSha256,
    untrustedInstallSourceDetection: on('untrusted_install_source'),
    repackagingDetection: on('repackage'),
    // Network security — highRiskIpDetection asks the platform backend's
    // GET /v1/ip-risk (HMAC-signed with the credential pasted in "Backend
    // Sync"); UNAVAILABLE until a credential is configured.
    vpnDetection: on('vpn'),
    mitmDetection: on('mitm'),
    certificatePinHost: pinHost,
    certificatePins: pins,
    highRiskIpDetection: on('high_risk_ip'),
    // Privacy & screen
    overlayDetection: on('overlay'),
    accessibilityDetection: on('accessibility'),
    externalDisplayDetection: on('external_display'),
    // Android 14+, DETECT_SCREEN_CAPTURE (AndroidManifest.xml).
    screenshotEventDetection: on('screenshot_event'),
    // Newer detectors (Tasks 3a-3c). sim_change and vishing_call need
    // READ_PHONE_STATE ("Grant permissions" in the Trial checks card);
    // mock_location needs location (granted in Settings). malware_reputation
    // uses the backend's signed list (key from the credential), or, with the
    // switch in the Trial checks card, the test list in
    // lib/test_reputation_list.dart.
    mockLocationDetection: on('mock_location'),
    timeSpoofingDetection: on('time_spoofing'),
    unsafeWifiDetection: on('unsafe_wifi'),
    screenRecordingDetection: on('screen_recording'),
    vishingCallDetection: on('vishing_call'),
    simChangeDetection: on('sim_change'),
    thirdPartyKeyboardDetection: on('third_party_keyboard'),
    taskHijackDetection: on('task_hijack'),
    deviceStateAttestationDetection: on('device_state_attestation'),
    malwareReputationDetection: on('malware_reputation'),
    malwareReputationListJson: useTestReputationList ? testReputationListJson : null,
    malwareReputationPublicKey: useTestReputationList ? testReputationPublicKey : null,
    malwareReputationAutoUpdate: !useTestReputationList,
    // Evidence envelopes (device-key signed) instead of legacy HMAC batches;
    // the first delivery registers this device with the backend.
    useEvidenceEnvelope: true,
    // Task 8.1 fraud signals and the session risk / transaction API (the
    // "Fraud risk" screen). The id-hash salt comes from the pasted credential
    // (account_hash_salt); without it login/transaction report UNAVAILABLE.
    remoteControlAppDetection: on('remote_control_app'),
    screenSharingDetection: on('screen_sharing_risk'),
    otpInterceptionDetection: on('otp_interception_risk'),
    smsReaderAbuseDetection: on('sms_reader_abuse'),
    otpForwardingDetection: on('otp_forwarding_risk'),
    sessionRiskScoring: true,
    // Task 10.0 signed remote configuration (GET /v1/config), verified with
    // the credential's config_public_key; reported as remote_config_rejected.
    // remoteManagedDetectors stays empty, so a remote config can change
    // intervals and thresholds but never the Feature lab's on/off choices.
    remoteConfigEnabled: on('remote_config_rejected'),
  );
}

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
  /// Whether the running session guards the clipboard (see _startSession).
  bool _clipboardGuarded = false;

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

  // ── Feature lab ──────────────────────────────────────────────────────────
  /// Which of the 43 features are on; changing it restarts the session.
  final _lab = FeatureLab();

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
    _lab
      ..onEnabledChanged = _applyFeatures
      ..onRefresh = (() async => _session?.refreshNow())
      ..onRefreshRemoteConfig = (() async => _session?.refreshRemoteConfigNow())
      ..tryItPanel = _tryItPanel;
    _bootstrap();
  }

  /// Every change here also rebuilds the Feature lab pages, whose "Try it"
  /// panels are built from this state (_tryItPanel).
  @override
  void setState(VoidCallback fn) {
    super.setState(fn);
    _lab.ownerChanged();
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
    _lab.dispose();
    RaspSecurityEventShipper.onShipError = null;
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Re-check on resume — Developer Options / a cable can change while
    // the app was backgrounded; a stale cached value is a false sense of
    // security on a banking screen.
    if (state == AppLifecycleState.resumed) {
      // Text copied in another app while this one was in the background
      // would still be pastable here: wipe it while protection is on.
      if (_lab.isEnabled('clipboard_protection')) unawaited(RaspSecurityControls.clearClipboard());
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
        enabledFeatures: _lab.enabled,
      );

  /// A feature was switched in the Feature lab: restart the session with it.
  Future<void> _applyFeatures() async {
    _lab.applying = true;
    try {
      await _restartSession();
    } finally {
      if (mounted) _lab.applying = false;
    }
  }

  Future<void> _setTestReputationList(bool on) async {
    setState(() => _useTestReputationList = on);
    await _restartSession();
  }

  Future<void> _startSession(RaspLeanConfig config) async {
    final session = await RaspLeanSession.start(config);
    // The guard clears only copies made after it starts; wipe what is
    // already on the clipboard so nothing copied earlier can be pasted.
    // Only when protection turns on — not on every restart, since any
    // feature switched in the Feature lab restarts the session.
    if (config.clipboardProtection && !_clipboardGuarded) await RaspSecurityControls.clearClipboard();
    _clipboardGuarded = config.clipboardProtection;
    _stateSub = session.stateStream.listen((state) {
      _resultLogger?.log(state);
      _lab.update(state);
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
  /// A restart was asked for while one ran (e.g. several features switched
  /// quickly); it runs once more afterwards with the latest settings.
  bool _restartAgain = false;

  /// Stops the session and starts it again with the current pin settings.
  /// Never hangs: dispose and start each wait at most 2 s for the native side
  /// (RaspLeanSession.nativeCallTimeout), then continue. A failure is shown
  /// instead of leaving the screen without a session. A request while a
  /// restart runs is not started in parallel: one more restart follows, so
  /// the last settings always apply.
  Future<void> _restartSession() async {
    if (_restarting) {
      _restartAgain = true;
      return;
    }
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
    if (_restartAgain && mounted) {
      _restartAgain = false;
      await _restartSession();
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

  // ── Clipboard ────────────────────────────────────────────────────────────

  Future<void> _clearClipboardNow() async {
    await RaspSecurityControls.clearClipboard();
    setState(() => _pasteResult = null);
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

    // Joining Wi-Fi gets a notice; an unsafe network (open, WEP, captive
    // portal) gets a warning, and unsafe_wifi DETECTED reaches the
    // dashboard as a medium alert with the next shipped event.
    if (wifiChangeAlert(previous, current) case final wifi?) {
      _showBanner(wifi.message, color: wifi.unsafe ? Colors.red.shade700 : Colors.blueGrey.shade700);
    }
  }

  void _showBanner(String message, {Color? color}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: color ?? Colors.orange.shade800),
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

  // ── Clipboard test (Clipboard Protection page) ───────────────────────────

  /// What "Paste here" got the last time, or null before the first paste.
  String? _pasteResult;

  Future<void> _copyTestText() async {
    final text = _clipboardTestController.text.trim();
    await Clipboard.setData(ClipboardData(text: text.isEmpty ? 'ACCOUNT 1234 5678 9012' : text));
    setState(() => _pasteResult = null);
    await _session?.refreshNow();
  }

  /// Reads the clipboard the way a paste would: with protection on, the
  /// copy has already been wiped, so this shows that nothing comes back.
  Future<void> _pasteTestText() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text ?? '';
    if (!mounted) return;
    setState(() => _pasteResult = text.isEmpty
        ? 'Nothing to paste — the clipboard is empty.'
        : 'Pasted: "$text"');
  }

  // ── Feature pages: "Try it" panels ───────────────────────────────────────

  /// The controls a feature's page shows under "Try it", built from this
  /// screen's state so they work exactly as they did on the old main screen.
  /// Empty for features that need nothing beyond Enable / Disable.
  List<Widget> _tryItPanel(BuildContext context, String id) {
    const hint = TextStyle(fontSize: 12, color: Colors.black54);
    final usb = _state.usb;
    Widget row(String label, Widget pill) => Row(children: [Expanded(child: Text(label)), pill]);
    Widget refresh() => Align(
          alignment: Alignment.centerRight,
          child: TextButton.icon(
            onPressed: () => _session?.refreshNow(),
            icon: const Icon(Icons.refresh),
            label: const Text('Refresh now'),
          ),
        );
    List<Widget> phonePermission({required bool simBaseline}) => [
          Text('Phone permission (READ_PHONE_STATE): ${phonePermissionLabel(_phonePermission)}',
              key: const Key('phone-permission')),
          const Text('Needed by SIM change and Call during app use.', style: hint),
          const SizedBox(height: 8),
          Wrap(spacing: 8, children: [
            FilledButton.icon(
              key: const Key('grant-permissions'),
              onPressed: _grantPhonePermission,
              icon: const Icon(Icons.phone_android),
              label: const Text('Grant permissions'),
            ),
            if (_phonePermission == PermissionStatus.permanentlyDenied)
              TextButton(onPressed: openSettings, child: const Text('Open app settings')),
          ]),
          if (_phoneRecheck != null)
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text(_phoneRecheck!, key: const Key('phone-recheck'), style: const TextStyle(fontSize: 13)),
            ),
          if (simBaseline && kDebugMode) ...[
            const Divider(height: 24),
            OutlinedButton.icon(
              key: const Key('reset-sim-baseline'),
              onPressed: _resetSimBaseline,
              icon: const Icon(Icons.restart_alt),
              label: const Text('Reset SIM baseline'),
            ),
            const Text(
              'Debug builds only. The next check stores a new baseline and reports UNKNOWN "baseline stored".',
              style: hint,
            ),
          ],
        ];

    switch (id) {
      case 'screenshot_protection':
        return [
          row('Screenshots & screen recording',
              _StatusPill(
                state: triFrom(_lab.isEnabled(id) ? (_state.screenshotActive ?? true) : false),
                yesLabel: 'Blocked',
                noLabel: 'Not blocked',
                yesIsGood: true,
              )),
          const SizedBox(height: 4),
          const Text(
            'FLAG_SECURE blocks both still screenshots and screen recording/casting. Take a screenshot '
            'or start a recording now — it fails or shows black while the feature is enabled.',
            style: hint,
          ),
        ];
      case 'usb_connection':
        return [
          row('USB cable / dock connected',
              _StatusPill(state: triFrom(usb.usbConnected), yesLabel: 'Connected', noLabel: 'Not connected')),
          const SizedBox(height: 4),
          Text('Connected USB device count: ${usb.connectedDeviceCount}', style: const TextStyle(fontSize: 13)),
          refresh(),
        ];
      case 'adb_enabled':
        return [
          row('USB debugging (ADB) enabled',
              _StatusPill(state: triFrom(usb.usbDebuggingEnabled), yesLabel: 'ADB ON', noLabel: 'ADB off')),
          refresh(),
          SwitchListTile(
            key: const Key('close-on-usb-debugging'),
            contentPadding: EdgeInsets.zero,
            title: const Text('Close the app when USB debugging turns on'),
            subtitle: const Text(
              'Off by default. When off, developer options, ADB and USB only '
              'show the warning banner. Applies the next time ADB turns on.',
              style: TextStyle(fontSize: 12),
            ),
            value: _closeOnUsbDebugging,
            onChanged: (value) => setState(() => _closeOnUsbDebugging = value),
          ),
        ];
      case 'developer_mode':
        return [
          row('Developer options unlocked',
              _StatusPill(state: triFrom(usb.developerModeEnabled), yesLabel: 'Unlocked', noLabel: 'Locked')),
          refresh(),
        ];
      case 'clipboard_protection':
        final evidence = _state.clipboardEvidence;
        return [
          row('Clipboard',
              _StatusPill(
                state: triFrom(_lab.isEnabled(id) ? (_state.clipboardActive ?? true) : false),
                yesLabel: 'Guarding',
                noLabel: 'Off',
                yesIsGood: true,
              )),
          const SizedBox(height: 12),
          TextField(
            key: const Key('clipboard-test-field'),
            controller: _clipboardTestController,
            decoration: const InputDecoration(
              labelText: 'Test text (empty: a sample account number)',
              border: OutlineInputBorder(),
              isDense: true,
            ),
          ),
          const SizedBox(height: 8),
          Wrap(spacing: 8, runSpacing: 4, children: [
            FilledButton.tonalIcon(
              key: const Key('clipboard-copy'),
              onPressed: _copyTestText,
              icon: const Icon(Icons.copy),
              label: const Text('Copy'),
            ),
            FilledButton.tonalIcon(
              key: const Key('clipboard-paste'),
              onPressed: _pasteTestText,
              icon: const Icon(Icons.content_paste),
              label: const Text('Paste here'),
            ),
            OutlinedButton.icon(
              key: const Key('clipboard-clear'),
              onPressed: _clearClipboardNow,
              icon: const Icon(Icons.cleaning_services),
              label: const Text('Clear clipboard now'),
            ),
          ]),
          if (_pasteResult != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(_pasteResult!,
                  key: const Key('clipboard-paste-result'), style: const TextStyle(fontWeight: FontWeight.w600)),
            ),
          const SizedBox(height: 8),
          Text(
            'Copies observed since the last check: ${evidence.changeCount}'
            '${evidence.lastChangeAt != null ? ' · last at ${evidence.lastChangeAt}' : ''}',
            style: hint,
          ),
          const Text(
            'Enabled: tap Copy (or select the text and copy it), then Paste here or paste in another app — '
            'nothing comes back. Disabled: the copied text pastes normally. The app never reads what '
            'was copied, only that a copy happened.',
            style: TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
          ),
        ];
      case 'sim_change':
        return phonePermission(simBaseline: true);
      case 'vishing_call':
        return phonePermission(simBaseline: false);
      case 'mock_location':
        return [
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
            value: _shareLocation,
            onChanged: _setShareLocation,
          ),
          if (_shareLocation) ...[
            Text(
              _lastFix == null
                  ? 'No fix yet.'
                  : 'Last fix: '
                      '${_lastFix!.latitude.toStringAsFixed(3)}, ${_lastFix!.longitude.toStringAsFixed(3)} '
                      '(mock flag: ${_lastFix!.isMock ?? "unknown"})',
              key: const Key('last-fix'),
              style: const TextStyle(fontSize: 12),
            ),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                key: const Key('read-location-now'),
                onPressed: _refreshLocation,
                icon: const Icon(Icons.my_location),
                label: const Text('Read location now'),
              ),
            ),
          ],
          Text(
            locationHeartbeatLabel(_state.locationHeartbeat, sharing: _shareLocation),
            key: const Key('location-heartbeat'),
            style: const TextStyle(fontSize: 12),
          ),
          Text('Mock location: ${detectorVerdict(_state, "mock_location")}', key: const Key('mock-location-result')),
        ];
      case 'mitm':
        return [
          Text(
            'TLS pin for mitm: ${_pinHost == null ? 'none (mitm reports pin_not_configured)' : '$_pinHost, ${_pins.length} pin(s)'}',
            key: const Key('pin-status'),
          ),
          const SizedBox(height: 8),
          TextField(
            key: const Key('pin-host'),
            controller: _pinHostController,
            decoration: const InputDecoration(
              labelText: 'Pinned host', hintText: 'api.example.com', border: OutlineInputBorder(), isDense: true,
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            key: const Key('pin-value'),
            controller: _pinController,
            decoration: const InputDecoration(
              labelText: 'SPKI pin(s)', hintText: 'sha256/<Base64 of 32 bytes>, comma-separated', border: OutlineInputBorder(), isDense: true,
            ),
          ),
          Wrap(spacing: 8, children: [
            FilledButton(key: const Key('apply-pin'), onPressed: _applyPin, child: const Text('Apply pin')),
            TextButton(key: const Key('clear-pin'), onPressed: _clearPin, child: const Text('No pin')),
          ]),
          const Text(
            'A wrong pin makes mitm DETECTED and lists the pins the server really sent (observed_pin) '
            'in the evidence; copy one to get a match.',
            style: hint,
          ),
        ];
      case 'malware_reputation':
        return [
          SwitchListTile(
            key: const Key('test-reputation-list'),
            contentPadding: EdgeInsets.zero,
            title: Text('Use the test list (flags $testReputationPackage)'),
            value: _useTestReputationList,
            onChanged: _setTestReputationList,
          ),
          Text('Result: ${detectorVerdict(_state, 'malware_reputation')}', key: const Key('reputation-result')),
          Text(
            _useTestReputationList
                ? 'A harmless test entry, so you can see DETECTED. To flag another installed app: '
                    'node tool/make_test_reputation_list.js <package>, then rebuild.'
                : 'Off: the signed list from your backend (Backend Sync credential), checked once a day. '
                    'UNAVAILABLE until the backend has a list and the credential carries its key; '
                    'UNKNOWN while the list is empty.',
            key: const Key('reputation-source'),
            style: hint,
          ),
        ];
      case 'high_risk_ip':
        return [
          Text(
            _shipperConfigured
                ? 'Backend: ${RaspSecurityEventShipper.configuredBackendHost ?? "configured"}'
                : 'Backend: not configured — paste a credential in Backend Sync on the Feature lab list.',
            key: const Key('ip-risk-backend'),
          ),
        ];
    }
    return const [];
  }

  @override
  Widget build(BuildContext context) {
    final status = _integrationStatus;
    if (status == null) {
      return Scaffold(
        appBar: AppBar(title: Text('Feature lab (${featureDisplayOrder.length})')),
        body: const Center(child: CircularProgressIndicator()),
      );
    }
    final warnings = postureWarnings(_state);
    return FeatureListScreen(
      lab: _lab,
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
      header: [
        _IntegrationBanner(status: status),
        if (warnings.isNotEmpty) ...[
          const SizedBox(height: 12),
          _PostureWarningBanner(warnings: warnings),
        ],
        const SizedBox(height: 12),
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
        const SizedBox(height: 4),
      ],
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
