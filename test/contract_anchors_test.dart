import 'dart:io';

import 'package:test/test.dart';

/// Contract-anchor gate: every `INVARIANT (tag)` declared in PROTOCOL.md must be anchored, the tag
/// being a code symbol or verbatim string that exists in `lib/` or `test/`. An invariant nothing
/// anchors is either unimplemented or a doc that has drifted (a symbol renamed or removed without
/// the doc following); both are failures to fix in the same change. Tags as symbols keep the
/// specification mechanically falsifiable.
void main() {
  test('every INVARIANT tag in PROTOCOL.md is anchored in lib/ or test/', () {
    final doc = File('PROTOCOL.md').readAsStringSync();
    // `(tag)` itself is the legend's placeholder, not an invariant.
    final tags = RegExp(r'INVARIANT \(([A-Za-z0-9_$]+)\)')
        .allMatches(doc)
        .map((m) => m.group(1)!)
        .where((tag) => tag != 'tag')
        .toSet();
    expect(tags, isNotEmpty, reason: 'PROTOCOL.md lost its INVARIANT markers?');

    final treeText = [
      for (final dir in ['lib', 'test'])
        ...Directory(dir)
            .listSync(recursive: true)
            .whereType<File>()
            .where((f) => f.path.endsWith('.dart') && !f.path.endsWith('contract_anchors_test.dart'))
            .map((f) => f.readAsStringSync()),
    ].join('\n');

    final missing = [
      for (final tag in tags)
        if (!RegExp('(?<![A-Za-z0-9_])${RegExp.escape(tag)}(?![A-Za-z0-9_])').hasMatch(treeText)) tag,
    ];
    expect(
      missing,
      isEmpty,
      reason:
          'INVARIANT tags with no anchor in lib/ or test/: $missing. The symbol was renamed or '
          'removed without PROTOCOL.md following, or the invariant is unimplemented. Fix the doc '
          'or the code in the same change.',
    );
  });

  test('the doc carries its maintenance rule and version line', () {
    final doc = File('PROTOCOL.md').readAsStringSync();
    expect(doc, contains('Last verified against the code'));
    expect(doc, contains('Update this document in the same change'));
  });
}
