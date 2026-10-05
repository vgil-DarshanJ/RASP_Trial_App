import 'dart:convert';

import 'package:flutter/services.dart' show AssetBundle;

/// Values the Android build writes before compiling Dart
/// (`generateRaspBuildConfig*` in android/app/build.gradle.kts) to
/// `assets/generated/rasp_build.json`. Missing in `flutter test` /
/// `flutter analyze` runs and builds without that task: then nothing is
/// configured and `tamper` reports UNKNOWN "not configured".
class TrialBuildConfig {
  const TrialBuildConfig({this.expectedSigningCertSha256, this.variant});

  static const assetPath = 'assets/generated/rasp_build.json';
  static const none = TrialBuildConfig();

  /// SHA-256 of the certificate this build is signed with (uppercase hex).
  final String? expectedSigningCertSha256;
  final String? variant;

  static TrialBuildConfig parse(String text) {
    final json = jsonDecode(text);
    if (json is! Map) return none;
    final hash = json['expectedSigningCertSha256'];
    return TrialBuildConfig(
      expectedSigningCertSha256: hash is String && RegExp(r'^[0-9A-F]{64}$').hasMatch(hash) ? hash : null,
      variant: json['variant'] as String?,
    );
  }

  static Future<TrialBuildConfig> load(AssetBundle bundle) async {
    try {
      return parse(await bundle.loadString(assetPath, cache: false));
    } catch (_) {
      return none;
    }
  }
}
