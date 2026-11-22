package android.webkit
annotation class JavascriptInterface
class WebView {
 var parent:Any?=null;fun destroy(){}
 val context=Any();val queued=java.util.concurrent.ConcurrentLinkedQueue<Runnable>();val urls=java.util.concurrent.CopyOnWriteArrayList<String>()
 fun post(run:Runnable):Boolean {queued.add(run);return true}
 fun loadUrl(url:String) {urls.add(url)}
 fun drain() {while(true)(queued.poll()?:break).run()}
}

open class JsResult {fun confirm(){};fun cancel(){}}
class JsPromptResult {fun confirm(value:String){};fun cancel(){}}
fun interface ValueCallback<T> {fun onReceiveValue(value:T?)}
