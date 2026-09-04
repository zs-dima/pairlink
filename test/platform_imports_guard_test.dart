import 'dart:io';

import 'package:test/test.dart';

/// Architecture guard: pairlink is pure Dart. It runs under plain `dart test`, including the Linux
/// CI leg and a docker container that reproduces platform socket-teardown differences. A single
/// `package:flutter` or `dart:ui` import breaks that silently: the package still compiles inside a
/// Flutter application while every out-of-app harness dies.
///
/// `dart:io` is allowed; sockets are the package's job.
void main() {
  test('pairlink lib stays Flutter-free (no package:flutter, no dart:ui)', () {
    final banned = RegExp(r'''import\s+['"](package:flutter|dart:ui)''');
    final offenders = <String>[];

    for (final entity in Directory('lib').listSync(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      for (final (index, line) in entity.readAsLinesSync().indexed) {
        if (banned.hasMatch(line)) offenders.add('${entity.path}:${index + 1}  ${line.trim()}');
      }
    }

    expect(
      offenders,
      isEmpty,
      reason:
          'pairlink must stay pure Dart (dart test / Linux CI / docker repro). Offending imports:\n'
          '${offenders.join('\n')}',
    );
  });
}
