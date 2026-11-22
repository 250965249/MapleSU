
import com.maplesu.core.ui.webui.SuFilePathHandler;
import com.maplesu.core.ui.webui.Insets;
import com.topjohnwu.superuser.Shell;
import android.webkit.WebResourceResponse;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.util.*;
import java.util.zip.GZIPOutputStream;

public class StaticHandlerMain {
  static void write(Path root,String name,String value) throws Exception {
    Path file=root.resolve(name); Files.createDirectories(file.getParent()); Files.writeString(file,value);
  }
  static void check(boolean value,String message) { if(!value)throw new AssertionError(message); }
  public static void main(String[] args) throws Exception {
    Path root=Paths.get(args[0]).toAbsolutePath();Files.createDirectories(root);
    write(root,"index.html","<!doctype html><html><head><meta charset='utf-8'><link rel='stylesheet' href='assets/style.css?rev=1'></head><body><p id='fixture'>Loading static module</p><script type='module' src='/assets/main.js?rev=1'></script></body></html>");
    write(root,"assets/style.css","#fixture { color: rgb(19, 37, 73); } body { background: rgb(240, 244, 248); }");
    write(root,"assets/main.js","const r = await fetch('../data/status.json?revision=1'); const v = await r.json(); document.querySelector('#fixture').textContent=v.message; document.documentElement.dataset.staticReady='yes';");
    write(root,"assets/worker.js","self.onmessage=event=>self.postMessage({kind:'same-origin',value:event.data});");
    write(root,"data/status.json","{\"message\":\"Normal static WebUI loaded\"}");
    Files.write(root.resolve("assets/fixture.wasm"),new byte[]{0,97,115,109,1,0,0,0});
    try(var out=new GZIPOutputStream(Files.newOutputStream(root.resolve("assets/icon.svgz")))) {
      out.write("<svg xmlns='http://www.w3.org/2000/svg'><path d='M0 0'/></svg>".getBytes(StandardCharsets.UTF_8));
    }
    write(root.getParent(),"outside.txt","outside");
    var handler=new SuFilePathHandler(new android.content.Context(),root.toFile(),new Shell(),Insets::new,flag->{});
    URI home=URI.create("https://mui.kernelsu.org/index.html");
    var urls=List.of(home,home.resolve("assets/style.css?rev=1"),home.resolve("/assets/main.js?rev=1"),
      home.resolve("/data/status.json?revision=1"),home.resolve("assets/fixture.wasm"),home.resolve("assets/icon.svgz"),home.resolve("missing.html"),home.resolve("assets/worker.js"));
    var expected=List.of("text/html","text/css","application/javascript","application/json","application/wasm","image/svg+xml");
    for(int i=0;i<urls.size();i++) {
      URI uri=urls.get(i); String path=uri.getPath().substring(1); // AssetLoader passes a decoded path, without query.
      WebResourceResponse response=handler.handle(path);
      byte[] body=response.getData()==null?null:response.getData().readAllBytes();
      if(i<6) check(body!=null && body.length>0,"missing "+uri);
      if(i<6) check(expected.get(i).equals(response.getMimeType()) ||
          (i==2 && "text/javascript".equals(response.getMimeType())),"MIME "+uri+"="+response.getMimeType());
      if(i==5) check(new String(body,StandardCharsets.UTF_8).startsWith("<svg"),"svgz not decompressed");
      if(i==6) check(body==null,"missing file unexpectedly readable");
      if(i==7) check(body!=null && ("application/javascript".equals(response.getMimeType()) ||
          "text/javascript".equals(response.getMimeType())),"worker MIME");
      System.out.println(Base64.getEncoder().encodeToString(uri.toString().getBytes(StandardCharsets.UTF_8))+"\t"+
        Objects.toString(response.getMimeType(),"")+"\t"+(body==null?"NULL":Base64.getEncoder().encodeToString(body)));
    }
    check(handler.handle("../outside.txt").getData()==null,"path escaped webroot");
    check(SuFilePathHandler.getCanonicalFileIfChild(root.toFile(),"../outside.txt")==null,"canonical child escaped");
    check(SuFilePathHandler.guessMimeType("fixture.unknown").equals("text/plain"),"unknown MIME");
  }
}
