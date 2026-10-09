package com.shieldsdk.rasp.trial

import io.flutter.embedding.engine.FlutterEngine

/** Profile build: no RASP_RESULT logger (the real one is debug-only, src/debug). */
object DebugResultLog {
    @Suppress("UNUSED_PARAMETER")
    fun register(engine: FlutterEngine) = Unit
}
