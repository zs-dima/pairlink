// A shared fixture, imported by the suites; its declaration is meant to be visible.
// ignore_for_file: avoid-top-level-members-in-tests
import 'package:pairlink/pairlink.dart';

/// The identity every test pairs under: a test brand, not any real application's.
const PairIdentity kTestIdentity = PairIdentity(brand: 'pltest', serviceType: '_pltest._tcp', scheme: 'pltest');
