// Main screen (Task 4.7 items 1 and 3), driven through the real dashboard
// widgets, the real results screen and the real RaspLeanSession state
// decoding. Fake: the native side — see test/support/fake_native.dart.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/lean_session.dart' show RaspDetectorDescriptor;

import 'support/fake_native.dart';

const _closeSetting = Key('close-on-usb-debugging');

void main() {
  testWidgets('developer options, ADB and USB show the warning banner and the app stays open (setting off by default)',
      (tester) async {
    final native = await bootTrialApp(tester);

    await emitState(tester, native, nativeState());
    expect(find.text('Device warning'), findsNothing);

    await emitState(tester, native, nativeState(adb: true, devMode: true, usb: true));
    expect(find.text('Device warning'), findsOneWidget);
    expect(find.text('Developer options are unlocked on this device.'), findsOneWidget);
    expect(find.text('USB debugging (ADB) is enabled.'), findsOneWidget);
    expect(find.text('A USB cable or dock is connected.'), findsOneWidget);

    await tester.pump(const Duration(seconds: 7));
    await tester.pump();
    expect(find.byType(AlertDialog), findsNothing);
    expect(native.platformCalls, isNot(contains('SystemNavigator.pop')));
    expect(find.text('Device warning'), findsOneWidget, reason: 'still on the main screen');

    await scrollTo(tester, find.byKey(_closeSetting));
    expect(tester.widget<SwitchListTile>(find.byKey(_closeSetting)).value, isFalse);
  });

  testWidgets('ADB already on at the first reading does not close the app', (tester) async {
    final native = await bootTrialApp(tester);

    await emitState(tester, native, nativeState(adb: true, devMode: true));
    await tester.pump(const Duration(seconds: 7));
    await tester.pump();

    expect(find.byType(AlertDialog), findsNothing);
    expect(native.platformCalls, isNot(contains('SystemNavigator.pop')));
    expect(find.text('USB debugging (ADB) is enabled.'), findsOneWidget);
  });

  testWidgets('with the setting switched on, ADB turning on still closes the app after the countdown', (tester) async {
    final native = await bootTrialApp(tester);
    await emitState(tester, native, nativeState());

    await scrollTo(tester, find.byKey(_closeSetting));
    await tester.tap(find.byKey(_closeSetting));
    await tester.pump();
    expect(tester.widget<SwitchListTile>(find.byKey(_closeSetting)).value, isTrue);

    await emitState(tester, native, nativeState(adb: true, devMode: true));
    expect(find.text('Developer Mode Detected'), findsOneWidget);
    expect(native.platformCalls, isNot(contains('SystemNavigator.pop')), reason: 'not before the countdown ends');

    await tester.pump(const Duration(seconds: 6));
    await tester.pump();
    expect(native.platformCalls, contains('SystemNavigator.pop'));
  });

  testWidgets('main screen uses the results screen headings and names; clipboard Guarding is green', (tester) async {
    final native = await bootTrialApp(tester);
    const reported = ['device_binding', 'mock_location', 'vpn', 'overlay', 'external_display', 'risky_app'];
    await emitState(tester, native, nativeState(detectors: {
      'device_binding': nativeCheck('device_binding', 'SECURE'),
      'mock_location': nativeCheck('mock_location', 'UNAVAILABLE', 'Location permission not granted'),
      'vpn': nativeCheck('vpn', 'DETECTED'),
      'overlay': nativeCheck('overlay', 'SECURE'),
      'external_display': nativeCheck('external_display', 'SECURE'),
      'risky_app': nativeCheck('risky_app', 'UNKNOWN'),
    }));

    // Clipboard card: "Guarding" in green, not the red used for findings.
    await scrollTo(tester, find.text('Guarding'));
    final guarding = tester.widget<Chip>(find.ancestor(of: find.text('Guarding'), matching: find.byType(Chip)));
    expect(guarding.backgroundColor, Colors.green);

    // Main screen detector card: headings in the shared order, then names.
    const headings = ['Device Integrity', 'Network Security', 'Privacy & Screen', 'Other'];
    for (final heading in headings) {
      await scrollTo(tester, find.text(heading));
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
      await scrollTo(tester, find.text(heading));
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
