package dev.maplesu.manager.runtime;

import android.app.Activity;
import android.app.Service;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.widget.TextView;
import dalvik.system.PathClassLoader;
import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.json.JSONObject;

/** Independent foreground test UID: production discovery and a fixed restricted SU command. */
public final class HookSuPeerActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText("Checking the published Hook endpoint from an independent application UID…");
        setContentView(view);
        new Thread(() -> {
            JSONObject report = new JSONObject();
            Parcel request = Parcel.obtain();
            try {
                report.put("callerUid", Process.myUid());
                String apk = getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).sourceDir;
                ClassLoader product = new PathClassLoader(apk, getClassLoader());
                IBinder endpoint = (IBinder) product.loadClass("dev.maplesu.manager.runtime.NativeSuDiscovery")
                    .getMethod("peek", int.class).invoke(null, Process.myUid());
                request.writeStrongBinder(endpoint);
                request.writeString("/system/bin/id -u; /system/bin/id -Z; /system/bin/getenforce");
                request.writeString("/"); request.writeByteArray(new byte[0]);
                request.writeStringArray(new String[]{"PATH=/system/bin"});
                request.writeInt(0); request.writeInt(-1); request.setDataPosition(0);
                Method run = NativeSuProbe.class.getDeclaredMethod("session", Service.class, Parcel.class);
                run.setAccessible(true);
                Bundle result = (Bundle) run.invoke(null, null, request);
                report.put("accepted", result.getBoolean("accepted"));
                report.put("finished", result.getBoolean("finished"));
                report.put("exitCode", result.getInt("exitCode", -1));
                report.put("stdout", new String(result.getByteArray("stdout") == null ? new byte[0] : result.getByteArray("stdout"), StandardCharsets.UTF_8));
                report.put("denial", result.getString("denialDetail"));
            } catch (Throwable error) {
                try { report.put("failure", error.toString()); } catch (Exception ignored) { }
            } finally {
                request.recycle();
                String text = report.toString();
                try { Files.write(new File(getFilesDir(), "hook-peer.json").toPath(), text.getBytes(StandardCharsets.UTF_8)); }
                catch (Exception ignored) { }
                runOnUiThread(() -> view.setText(text));
            }
        }, "hook-peer").start();
    }
}
