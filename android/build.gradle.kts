allprojects {
    repositories {
        google()
        mavenCentral()
        mavenLocal()
        // RASP Shield's android_core is published via JitPack
        // (com.github.Vedant0Nisar:RaShield-SDK — see :rasp_shield's own
        // build.gradle.kts). Gradle resolves a project dependency's own
        // transitive external dependencies using the CONSUMING project's
        // repositories, not the library's — so this one line belongs
        // here, on the app that actually uses the SDK, not on the SDK
        // module itself. Every real consumer of this SDK needs this
        // exact line in their own root build.gradle.kts (or the
        // dependencyResolutionManagement block in settings.gradle.kts,
        // depending on their project's Gradle template).
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
