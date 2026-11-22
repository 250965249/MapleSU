package android.os
class Looper {companion object {fun getMainLooper()=Looper()}}
class Handler(val looper:Looper) {fun post(run:Runnable):Boolean {run.run();return true}}
