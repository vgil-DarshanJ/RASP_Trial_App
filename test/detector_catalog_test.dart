// Shared detector catalog (Task 4.7 item 3): the main screen and the results
// screen use the same headings, order and names. Real: detector_catalog.dart
// and the plugin's RaspDetectorDescriptor. No platform channel involved.
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/lean_session.dart' show RaspDetectorDescriptor;
import 'package:rasp_trial/detector_catalog.dart';

void main() {
  test('every trial detector has its own name, never the generic "Security Check"', () {
    for (final id in trialDetectorIds) {
      expect(RaspDetectorDescriptor.forId(id).isGeneric, isFalse, reason: id);
      expect(detectorName(id), isNot('Security Check'), reason: id);
    }
  });

  test('trial detectors are grouped under the category headings, in order', () {
    final groups = groupByCategory(trialDetectorIds);
    expect(groups.map((g) => g.$1).toList(), [
      'Device Integrity',
      'Runtime Protection',
      'App Integrity',
      'Network Security',
      'Privacy & Screen',
      'Other',
    ]);
    final grouped = groups.expand((g) => g.$2).toList();
    expect(grouped.length, trialDetectorIds.length, reason: 'each id appears once');
    expect(grouped.toSet(), trialDetectorIds.toSet());
  });

  test('main screen groups = results screen groups without the ids that have not reported', () {
    const reported = ['vpn', 'overlay', 'root_jailbreak', 'mock_location', 'frida', 'risky_app', 'zz_unknown'];
    final mainGroups = groupByCategory(reportedDetectorIds(reported));
    final resultGroups = groupByCategory(displayedDetectorIds(reported));
    final resultHeadings = resultGroups.map((g) => g.$1).toList();
    final resultIds = {for (final (heading, ids) in resultGroups) heading: ids};

    expect(mainGroups.expand((g) => g.$2).toSet(), reported.toSet());
    var lastHeadingIndex = -1;
    for (final (heading, ids) in mainGroups) {
      final index = resultHeadings.indexOf(heading);
      expect(index, greaterThan(lastHeadingIndex), reason: '$heading: same heading order');
      lastHeadingIndex = index;
      expect(ids, resultIds[heading]!.where(ids.contains).toList(), reason: '$heading: same ids, same order');
    }
  });

  test('an id the plugin does not know is listed under Other', () {
    final (heading, ids) = groupByCategory(['zz_unknown']).single;
    expect(heading, 'Other');
    expect(ids, ['zz_unknown']);
  });
}
