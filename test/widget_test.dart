// Basic smoke test — confirms the dashboard boots and shows its app bar.
// Does not exercise real native calls (no platform channel in the test
// environment); RaspSecurityControls calls resolve to null/unsupported,
// which the UI already renders as "Unknown"/pill states rather than
// crashing — see main.dart's triFrom().

import 'package:flutter_test/flutter_test.dart';

import 'package:rasp_trial/main.dart';

void main() {
  testWidgets('Security dashboard boots and shows its app bar',
      (WidgetTester tester) async {
    await tester.pumpWidget(const RaspTrialApp());
    await tester.pump();

    expect(find.text('RASP Shield — Lean Trial'), findsOneWidget);
  });
}
