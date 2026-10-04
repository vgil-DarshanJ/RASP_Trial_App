package com.example.rasp_trial

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // Debug builds: registers the RASP_RESULT logcat channel
        // (src/debug). Release and profile builds: does nothing (src/release,
        // src/profile), so the logger is not in those APKs.
        DebugResultLog.register(flutterEngine)
    }
}
