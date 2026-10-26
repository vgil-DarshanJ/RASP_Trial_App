// Basic smoke test — confirms the app boots on the Feature lab.
// Does not exercise real native calls (no platform channel in the test
// environment); RaspSecurityControls calls resolve to null/unsupported,
// which the UI already renders as "Unknown"/pill states rather than
// crashing — see main.dart's triFrom().

import 'package:flutter_test/flutter_test.dart';

import 'package:rasp_trial/main.dart';

void main() {
  testWidgets('the app boots on the Feature lab',
      (WidgetTester tester) async {
    await tester.pumpWidget(const RaspTrialApp());
    await tester.pump();

    expect(find.text('Feature lab (43)'), findsOneWidget);
  });
}
