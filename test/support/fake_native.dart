// Shared fake native side for the trial app's widget tests. Faked: the
// plugin's method channel (RaspNativeChannel.testInvokeHandler), the native
// lean-state event stream (mock stream handler), flutter_secure_storage's
// channel ("nothing stored"), the platform channel SystemNavigator.pop uses
// (recorded, nothing closes) and the READ_PHONE_STATE status. Everything
// above the channels — the dashboard, the results screen, RaspLeanSession's
// state decoding — is the real code.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_trial/main.dart';
import 'package:rasp_trial/permission_onboarding.dart';

const _leanStateChannel = EventChannel('com.shieldsdk.security/lean_state');
// Answered with "nothing stored", so the credential restore at startup
// finishes instead of waiting forever.
const _secureStorageChannel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
// The debug-only RASP_RESULT logcat channel (android/app/src/debug): recorded.
const _resultLogChannel = MethodChannel('rasp_trial/debug_result_log');

class FakeNative {
  /// Every plugin method call, in order, with its arguments.
  final calls = <(String, Object?)>[];
  /// Methods sent on the platform channel (e.g. SystemNavigator.pop).
  final platformCalls = <String>[];
  /// Lines sent to the RASP_RESULT logcat channel.
  final resultLogLines = <String>[];
  /// Answers plugin methods; `true` for anything it does not handle.
  Object? Function(String method, Object? arguments)? answer;
  /// Answers saved for the first-launch permission explanation.
  final savedIntroAnswers = <String>[];
  /// How often "Open Settings" was used.
  int settingsOpened = 0;
  late MockStreamHandlerEventSink events;

  List<String> get methods => [for (final c in calls) c.$1];
  List<Object?> argumentsOf(String method) => [for (final c in calls) if (c.$1 == method) c.$2];
}

/// Starts the app against [FakeNative] and waits until the lean session runs.
/// [storedCredential]: what secure storage returns for the saved backend
/// credential (a test value), so the app starts already configured.
/// [introAnswer]: the stored answer to the first-launch permission
/// explanation; `'continue'` (already answered) by default, `null` = first
/// launch, so the explanation is shown.
Future<FakeNative> bootTrialApp(
  WidgetTester tester, {
  PermissionStatus phoneStatus = PermissionStatus.denied,
  String? storedCredential,
  String? introAnswer = 'continue',
}) async {
  final native = FakeNative();
  MockStreamHandlerEventSink? events;
  final messenger = tester.binding.defaultBinaryMessenger;
  final originalRequest = requestPhonePermission;
  final originalStatus = phonePermissionStatus;
  final originalReadIntro = readPermissionIntroAnswer;
  final originalSaveIntro = savePermissionIntroAnswer;
  final originalOpenSettings = openSettings;
  phonePermissionStatus = () async => phoneStatus;
  readPermissionIntroAnswer = () async => native.savedIntroAnswers.isNotEmpty ? native.savedIntroAnswers.last : introAnswer;
  savePermissionIntroAnswer = (answer) async => native.savedIntroAnswers.add(answer);
  openSettings = () async {
    native.settingsOpened++;
    return true;
  };

  RaspNativeChannel.testInvokeHandler = (method, arguments) async {
    native.calls.add((method, arguments));
    return native.answer?.call(method, arguments) ?? true;
  };
  messenger.setMockStreamHandler(
    _leanStateChannel,
    // Block body: the value onListen returns is sent back as the reply.
    MockStreamHandler.inline(onListen: (arguments, sink) {
      events = sink;
    }),
  );
  messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
    native.platformCalls.add(call.method);
    return null;
  });
  messenger.setMockMethodCallHandler(_secureStorageChannel, (call) async => call.method == 'read' ? storedCredential : null);
  messenger.setMockMethodCallHandler(_resultLogChannel, (call) async {
    native.resultLogLines.add(call.arguments as String);
    return true;
  });
  addTearDown(() {
    messenger.setMockMethodCallHandler(_resultLogChannel, null);
    RaspNativeChannel.testInvokeHandler = null;
    requestPhonePermission = originalRequest;
    phonePermissionStatus = originalStatus;
    readPermissionIntroAnswer = originalReadIntro;
    savePermissionIntroAnswer = originalSaveIntro;
    openSettings = originalOpenSettings;
    messenger.setMockStreamHandler(_leanStateChannel, null);
    messenger.setMockMethodCallHandler(SystemChannels.platform, null);
    messenger.setMockMethodCallHandler(_secureStorageChannel, null);
  });

  await tester.pumpWidget(const RaspTrialApp());
  final resultsButton = find.byTooltip('Detector results');
  for (var i = 0; i < 20; i++) {
    await tester.pump();
    final started = resultsButton.evaluate().isNotEmpty &&
        tester.widget<IconButton>(find.ancestor(of: resultsButton, matching: find.byType(IconButton))).onPressed != null;
    if (started) break;
  }
  expect(events, isNotNull, reason: 'the session listens to the native state stream');
  native.events = events!;
  return native;
}

Future<void> emitState(WidgetTester tester, FakeNative native, Map<String, Object?> state) async {
  native.events.success(state);
  await tester.pump();
  await tester.pump();
}

Future<void> scrollTo(WidgetTester tester, Finder finder) async {
  await tester.scrollUntilVisible(finder, 200, scrollable: find.byType(Scrollable).first);
  await tester.ensureVisible(finder);
  await tester.pump();
}

/// One native lean-state emission, in the map shape the plugin decodes.
Map<String, Object?> nativeState({
  bool adb = false,
  bool devMode = false,
  bool usb = false,
  Map<String, Object?> detectors = const {},
}) =>
    {
      'screenshotActive': true,
      'usbConnected': usb,
      'usbDebuggingEnabled': adb,
      'developerModeEnabled': devMode,
      'usbDeviceCount': usb ? 1 : 0,
      'clipboardActive': true,
      'clipboardChangeCount': 0,
      'extendedDetectors': detectors,
    };

Map<String, Object?> nativeCheck(String id, String status, [String? reason, int observedAtMillis = 0]) => {
      'detectorId': id,
      'status': status,
      'reason': reason,
      'evidence': const <Object?>[],
      'observedAtMillis': observedAtMillis,
    };
