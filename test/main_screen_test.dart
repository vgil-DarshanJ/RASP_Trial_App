// Main screen (Task 4.7 items 1 and 3), driven through the real dashboard
// widgets, the real results screen and the real RaspLeanSession state
// decoding. Fake: the native method channel (RaspNativeChannel
// .testInvokeHandler answers every call with true), the native lean-state
// event stream (mock stream handler) and the platform channel
// SystemNavigator.pop uses (calls are recorded, nothing closes).
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/lean_session.dart' show RaspDetectorDescriptor;
import 'package:rasp_trial/main.dart';

const _leanStateChannel = EventChannel('com.shieldsdk.security/lean_state');
// flutter_secure_storage's channel: answered with "nothing stored", so the
// backend credential restore at startup finishes instead of waiting forever.
const _secureStorageChannel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
const _closeSetting = Key('close-on-usb-debugging');

/// One native lean-state emission, in the map shape the plugin decodes.
Map<String, Object?> _native({
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

Map<String, Object?> _check(String id, String status, [String? reason]) => {
      'detectorId': id,
      'status': status,
      'reason': reason,
      'evidence': const <Object?>[],
      'observedAtMillis': 0,
    };

/// Starts the app with the fake native side and waits until the lean
/// session is running. Returns the sink that pushes native states.
Future<MockStreamHandlerEventSink> _boot(WidgetTester tester, List<String> platformCalls) async {
  MockStreamHandlerEventSink? events;
  final messenger = tester.binding.defaultBinaryMessenger;
  RaspNativeChannel.testInvokeHandler = (method, arguments) async => true;
  messenger.setMockStreamHandler(
    _leanStateChannel,
    // Block body: the value onListen returns is sent back as the reply.
    MockStreamHandler.inline(onListen: (arguments, sink) {
      events = sink;
    }),
  );
  messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
    platformCalls.add(call.method);
    return null;
  });
  messenger.setMockMethodCallHandler(_secureStorageChannel, (call) async => null);
  addTearDown(() {
    RaspNativeChannel.testInvokeHandler = null;
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
  return events!;
}

Future<void> _emit(WidgetTester tester, MockStreamHandlerEventSink events, Map<String, Object?> state) async {
  events.success(state);
  await tester.pump();
  await tester.pump();
}

Future<void> _scrollTo(WidgetTester tester, Finder finder) async {
  await tester.scrollUntilVisible(finder, 200, scrollable: find.byType(Scrollable).first);
  await tester.ensureVisible(finder);
  await tester.pump();
}

void main() {
  testWidgets('developer options, ADB and USB show the warning banner and the app stays open (setting off by default)',
      (tester) async {
    final platformCalls = <String>[];
    final events = await _boot(tester, platformCalls);

    await _emit(tester, events, _native());
    expect(find.text('Device warning'), findsNothing);

    await _emit(tester, events, _native(adb: true, devMode: true, usb: true));
    expect(find.text('Device warning'), findsOneWidget);
    expect(find.text('Developer options are unlocked on this device.'), findsOneWidget);
    expect(find.text('USB debugging (ADB) is enabled.'), findsOneWidget);
    expect(find.text('A USB cable or dock is connected.'), findsOneWidget);

    await tester.pump(const Duration(seconds: 7));
    await tester.pump();
    expect(find.byType(AlertDialog), findsNothing);
    expect(platformCalls, isNot(contains('SystemNavigator.pop')));
    expect(find.text('Device warning'), findsOneWidget, reason: 'still on the main screen');

    await _scrollTo(tester, find.byKey(_closeSetting));
    expect(tester.widget<SwitchListTile>(find.byKey(_closeSetting)).value, isFalse);
  });

  testWidgets('ADB already on at the first reading does not close the app', (tester) async {
    final platformCalls = <String>[];
    final events = await _boot(tester, platformCalls);

    await _emit(tester, events, _native(adb: true, devMode: true));
    await tester.pump(const Duration(seconds: 7));
    await tester.pump();

    expect(find.byType(AlertDialog), findsNothing);
    expect(platformCalls, isNot(contains('SystemNavigator.pop')));
    expect(find.text('USB debugging (ADB) is enabled.'), findsOneWidget);
  });

  testWidgets('with the setting switched on, ADB turning on still closes the app after the countdown', (tester) async {
    final platformCalls = <String>[];
    final events = await _boot(tester, platformCalls);
    await _emit(tester, events, _native());

    await _scrollTo(tester, find.byKey(_closeSetting));
    await tester.tap(find.byKey(_closeSetting));
    await tester.pump();
    expect(tester.widget<SwitchListTile>(find.byKey(_closeSetting)).value, isTrue);

    await _emit(tester, events, _native(adb: true, devMode: true));
    expect(find.text('Developer Mode Detected'), findsOneWidget);
    expect(platformCalls, isNot(contains('SystemNavigator.pop')), reason: 'not before the countdown ends');

    await tester.pump(const Duration(seconds: 6));
    await tester.pump();
    expect(platformCalls, contains('SystemNavigator.pop'));
  });

  testWidgets('main screen uses the results screen headings and names; clipboard Guarding is green', (tester) async {
    final platformCalls = <String>[];
    final events = await _boot(tester, platformCalls);
    const reported = ['device_binding', 'mock_location', 'vpn', 'overlay', 'external_display', 'risky_app'];
    await _emit(tester, events, _native(detectors: {
      'device_binding': _check('device_binding', 'SECURE'),
      'mock_location': _check('mock_location', 'UNAVAILABLE', 'Location permission not granted'),
      'vpn': _check('vpn', 'DETECTED'),
      'overlay': _check('overlay', 'SECURE'),
      'external_display': _check('external_display', 'SECURE'),
      'risky_app': _check('risky_app', 'UNKNOWN'),
    }));

    // Clipboard card: "Guarding" in green, not the red used for findings.
    await _scrollTo(tester, find.text('Guarding'));
    final guarding = tester.widget<Chip>(find.ancestor(of: find.text('Guarding'), matching: find.byType(Chip)));
    expect(guarding.backgroundColor, Colors.green);

    // Main screen detector card: headings in the shared order, then names.
    const headings = ['Device Integrity', 'Network Security', 'Privacy & Screen', 'Other'];
    for (final heading in headings) {
      await _scrollTo(tester, find.text(heading));
      expect(find.text(heading), findsOneWidget);
    }
    for (final id in reported) {
      expect(find.text(RaspDetectorDescriptor.forId(id).title), findsOneWidget, reason: id);
    }
    expect(find.text('Security Check'), findsNothing);
    expect(find.text('Privacy Screen'), findsNothing, reason: 'old heading text');

    // Results screen: the same headings and names.
    await tester.tap(find.byTooltip('Detector results'));
    await tester.pumpAndSettle();
    expect(find.text('Detector results'), findsOneWidget);
    for (final heading in headings) {
      await _scrollTo(tester, find.text(heading));
      expect(find.text(heading), findsOneWidget);
    }
    // Scrolling back up from the bottom, so bottom-most first.
    for (final id in reported.reversed) {
      final title = '${RaspDetectorDescriptor.forId(id).title}  ($id)';
      await tester.scrollUntilVisible(find.text(title), -200, scrollable: find.byType(Scrollable).first);
      expect(find.text(title), findsOneWidget);
    }
  });
}
