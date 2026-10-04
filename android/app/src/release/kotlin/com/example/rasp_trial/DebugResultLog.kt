package com.example.rasp_trial

import io.flutter.embedding.engine.FlutterEngine

/** Release build: no RASP_RESULT logger (the real one is debug-only, src/debug). */
object DebugResultLog {
    @Suppress("UNUSED_PARAMETER")
    fun register(engine: FlutterEngine) = Unit
}
