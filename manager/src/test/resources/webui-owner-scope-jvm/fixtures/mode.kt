package dev.maplesu.manager.workmode

enum class WorkMode { KSU, ULTRA }
class ModeActivation
object ModeRuntime {
    var active = WorkMode.ULTRA
    var activation = ModeActivation()
}
