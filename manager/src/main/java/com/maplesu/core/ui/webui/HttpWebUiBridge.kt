package com.maplesu.core.ui.webui

import android.os.Handler
import android.os.Looper
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.webkit.ScriptHandler
import androidx.webkit.WebViewCompat
import com.maplesu.core.ui.webui.file.FileInputStreamInterface
import com.maplesu.core.ui.webui.file.FileInterface
import com.maplesu.core.ui.webui.file.FileOutputStreamInterface
import com.maplesu.core.ui.webui.file.KsuIO
import com.maplesu.core.ui.webui.file.RandomAccessFileInterface
import com.maplesu.core.ui.webui.pm.KsuPm
import dev.maplesu.manager.workmode.ModeRuntime
import org.json.JSONArray
import org.json.JSONObject
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

/** Synchronous legacy API for providers with document-start scripts but no restricted builder. */
internal class HttpWebUiBridge(
    private val state: WebUIState,
    private val view: WebView,
    commands: WebViewInterface,
    downloads: WebUIDownloadInterface,
) : AutoCloseable {
    private val roots = mapOf("ksu" to commands, "ksu_download" to downloads)
    private val activation = ModeRuntime.activation
    private val token = AtomicReference(SecureRandom().generateSeed(32).joinToString("") { "%02x".format(it) })
    private var script: ScriptHandler? = null

    fun install(origin: ModuleWebOrigin) {
        view.addJavascriptInterface(this, INTERFACE)
        val installed = WebViewCompat.addDocumentStartJavaScript(view, documentScript(), setOf(origin.value))
        synchronized(this) {
            if (token.get() != null) script = installed else {
                installed.remove()
                view.removeJavascriptInterface(INTERFACE)
            }
        }
    }

    override fun close() {
        if (token.getAndSet(null) == null) return
        val installed = synchronized(this) { script.also { script = null } }
        Handler(Looper.getMainLooper()).post {
            installed?.remove()
            view.removeJavascriptInterface(INTERFACE)
        }
    }

    @JavascriptInterface
    fun invoke(proof: String?, request: String?): String {
        // The native object is visible to every frame. Only the exact-origin
        // document-start closure receives this page's unguessable capability.
        if (!acceptsCall(proof))
            return failure("WebUI page closed or origin denied")
        val response = try {
            val call = JSONObject(requireNotNull(request))
            var receiver: Any = roots[call.getString("root")] ?: error("Unknown WebUI bridge")
            val path = call.getJSONArray("path")
            for (index in 0 until path.length()) {
                val step = path.getJSONArray(index)
                val args = step.getJSONArray(1)
                val factory = method(receiver, step.getString(0), args.length())
                // These getters/factories construct wrappers only. Replaying them
                // avoids retaining an unbounded map of Java object handles.
                check(factory.returnType in objectTypes) { "Invalid WebUI object path" }
                receiver = requireNotNull(invokeMethod(receiver, factory, args))
            }
            val args = call.getJSONArray("args")
            val target = method(receiver, call.getString("method"), args.length())
            val value = invokeMethod(receiver, target, args)
            JSONObject().apply {
                when {
                    target.returnType == Void.TYPE -> put("kind", "void")
                    target.returnType in objectTypes -> {
                        put("kind", "object")
                        put("type", objectTypes.indexOf(target.returnType))
                    }
                    value is Number -> { put("kind", "number"); put("value", value.toString()) }
                    else -> { put("kind", "value"); put("value", value ?: JSONObject.NULL) }
                }
            }.toString()
        } catch (error: Exception) {
            val cause = (error as? InvocationTargetException)?.targetException ?: error
            failure(cause.message ?: cause.javaClass.simpleName)
        }
        return if (acceptsCall(proof)) response else failure("WebUI page closed or origin denied")
    }

    private fun acceptsCall(proof: String?): Boolean =
        proof != null && proof == token.get() && state.acceptsPage(view) && activation === ModeRuntime.activation

    private fun method(receiver: Any, name: String, count: Int): Method =
        requireNotNull(methods[receiver.javaClass]?.get(name to count)) { "Unknown WebUI method" }

    private fun invokeMethod(receiver: Any, method: Method, args: JSONArray): Any? =
        method.invoke(receiver, *method.parameterTypes.mapIndexed { index, type ->
            val value = args.getJSONArray(index)
            when (type) {
                String::class.java -> when (value.getString(0)) {
                    "null", "object" -> null
                    "undefined" -> "undefined"
                    else -> value.get(1).toString()
                }
                Boolean::class.javaPrimitiveType -> value.optBoolean(1, false).takeIf { value.getString(0) == "boolean" } ?: false
                else -> {
                    val number = if (value.getString(0) == "number") value.getString(1).toDouble() else 0.0
                    when (type) {
                        Int::class.javaPrimitiveType -> number.toInt()
                        Long::class.javaPrimitiveType -> number.toLong()
                        Float::class.javaPrimitiveType -> number.toFloat()
                        Double::class.javaPrimitiveType -> number
                        else -> error("Unsupported WebUI argument type")
                    }
                }
            }
        }.toTypedArray<Any?>())

    internal fun documentScript(): String {
        val schema = JSONArray(objectTypes.map { type ->
            JSONObject().apply {
                methods.getValue(type).keys.forEach { (name, count) ->
                    put(name, (optJSONArray(name) ?: JSONArray().also { put(name, it) }).put(count))
                }
            }
        })
        return """(function(){'use strict';
            var proof=${JSONObject.quote(requireNotNull(token.get()))},native=window.$INTERFACE;
            var schema=$schema;
            function encode(value){
                if(value===null)return ['null'];
                var type=typeof value;
                if(type==='number')return [type,String(value)];
                if(type==='string'||type==='boolean')return [type,value];
                return [type==='undefined'?'undefined':'object'];
            }
            function object(root,path,type){
                var result={},singletons={};
                Object.keys(schema[type]).forEach(function(name){
                    result[name]=function(){
                        var args=Array.prototype.map.call(arguments,encode);
                        var reply=JSON.parse(native.invoke(proof,JSON.stringify({root:root,path:path,method:name,args:args})));
                        if(reply.kind==='error')throw new Error(reply.message);
                        if(reply.kind==='void')return;
                        if(reply.kind==='number')return Number(reply.value);
                        if(reply.kind==='object'){
                            var next=path.concat([[name,args]]);
                            if(reply.type===$FILE_TYPE)return object(root,next,reply.type);
                            return singletons[name]||(singletons[name]=object(root,next,reply.type));
                        }
                        return reply.value;
                    };
                });
                return result;
            }
            window.ksu=object('ksu',[],$COMMAND_TYPE);
            window.ksu_download=object('ksu_download',[],$DOWNLOAD_TYPE);
        })();""".trimIndent()
    }

    private fun failure(message: String) = JSONObject().put("kind", "error").put("message", message).toString()

    companion object {
        internal const val INTERFACE = "__maplesu_http_bridge"
        private val objectTypes = listOf(WebViewInterface::class.java, WebUIDownloadInterface::class.java,
            KsuIO::class.java, FileInterface::class.java, FileInputStreamInterface::class.java,
            FileOutputStreamInterface::class.java, RandomAccessFileInterface::class.java, KsuPm::class.java)
        private const val COMMAND_TYPE = 0
        private const val DOWNLOAD_TYPE = 1
        private const val FILE_TYPE = 3
        private val methods = objectTypes.associateWith { type ->
            type.methods.filter { it.isAnnotationPresent(JavascriptInterface::class.java) }
                .associateBy { it.name to it.parameterTypes.size }
        }
    }
}
