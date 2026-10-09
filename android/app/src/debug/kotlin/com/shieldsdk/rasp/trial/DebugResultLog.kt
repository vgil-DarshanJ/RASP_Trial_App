package com.shieldsdk.rasp.trial

import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * DEBUG BUILDS ONLY (src/debug). Writes each line the Dart side sends to
 * logcat with tag RASP_RESULT, for phone smoke tests:
 *   adb logcat -d -s RASP_RESULT
 * Release and profile builds compile the no-op in src/release / src/profile.
 */
object DebugResultLog {
    const val TAG = "RASP_RESULT"
    const val CHANNEL = "rasp_trial/debug_result_log"

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "log") {
                Log.i(TAG, call.arguments as? String ?: "")
                result.success(true)
            } else {
                result.notImplemented()
            }
        }
    }
}
