package dev.maplesu.manager.runtime;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Keeps the peer separate from Manager; manual cached-handle checks survive Manager stopping. */
public final class BinderAdmissionPeerActivity extends Activity {
    private IBinder service;
    private TextView report;
    private boolean bound;
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) { service = binder; }
        @Override public void onServiceDisconnected(ComponentName name) { service = null; }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        report = new TextView(this);
        report.setText("Binder admission peer: waiting for instrumentation to transfer a Root handle.\nThis checks cached handles, not fresh discovery or su execution.");
        Button probe = new Button(this);
        probe.setText("Check cached Root Binder");
        probe.setOnClickListener(view -> checkCached());
        layout.addView(report); layout.addView(probe); setContentView(layout);
        bound = bindService(new Intent(this, BinderAdmissionPeerService.class), connection, Context.BIND_AUTO_CREATE);
        if ("dev.maplesu.manager.test.PROBE_COLD_BINDER".equals(getIntent().getAction())) checkCold(getIntent());
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if ("dev.maplesu.manager.test.PROBE_CACHED_BINDER".equals(intent.getAction())) checkCached();
        if ("dev.maplesu.manager.test.PROBE_COLD_BINDER".equals(intent.getAction())) checkCold(intent);
    }

    private void checkCold(Intent intent) {
        boolean foreground = intent.getBooleanExtra("foreground", false);
        String discovery = intent.getStringExtra("discovery");
        final String route = discovery == null ? "broadcast" : discovery;
        String requested = intent.getStringExtra("sessionChecks");
        final String checks = requested != null ? requested : intent.getBooleanExtra("realSessions", false) ? "sessions" : "echo";
        int delay = Math.max(0, Math.min(5, intent.getIntExtra("delaySeconds", 0)));
        new Thread(() -> {
            String message;
            try {
                if (delay != 0) Thread.sleep(delay * 1000L);
                String classpath = getApplicationInfo().sourceDir + ":" +
                    getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).sourceDir;
                ProcessBuilder launcher = new ProcessBuilder("/system/bin/app_process", "/system/bin",
                    BinderAdmissionColdClient.class.getName(), Boolean.toString(foreground), route, checks);
                launcher.environment().put("CLASSPATH", classpath);
                launcher.redirectErrorStream(true);
                java.lang.Process client = launcher.start();
                try (InputStream input = client.getInputStream(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                    byte[] bytes = new byte[512];
                    int size;
                    while ((size = input.read(bytes)) != -1) {
                        if (output.size() + size > 8192) {
                            client.destroy();
                            throw new IllegalStateException("Cold client output exceeds bound");
                        }
                        output.write(bytes, 0, size);
                    }
                    message = "COLD_APP_CLIENT exit=" + client.waitFor() + " " + output.toString(StandardCharsets.UTF_8.name()).trim();
                }
            } catch (Exception error) { message = "COLD_APP_CLIENT failed: " + error; }
            final String observed = message;
            Log.i("MapleSUBinderAdmission", observed);
            runOnUiThread(() -> report.setText(observed));
        }, "binder-admission-cold-client").start();
    }

    private void checkCached() {
        final IBinder peer = service;
        if (peer == null) { report.setText("Peer service is not connected"); return; }
        new Thread(() -> {
            Parcel request = Parcel.obtain(), response = Parcel.obtain();
            String text;
            try {
                request.writeInterfaceToken(BinderAdmissionPeerService.DESCRIPTOR);
                if (!peer.transact(IBinder.FIRST_CALL_TRANSACTION + 1, request, response, 0))
                    throw new IllegalStateException("Peer fixture transaction not handled");
                response.readException();
                Bundle result = response.readTypedObject(Bundle.CREATOR);
                if (result == null) throw new IllegalStateException("Peer reply missing");
                JSONObject observed = new JSONObject();
                observed.put("peerUid", result.getInt("peerUid", -1));
                observed.put("peerPid", result.getInt("peerPid", -1));
                observed.put("stage", result.getString("stage"));
                observed.put("failure", result.getString("failure"));
                for (String name : new String[]{"identity", "stdio"}) {
                    Bundle value = result.getBundle(name);
                    if (value != null) {
                        JSONObject fields = new JSONObject();
                        for (String key : value.keySet()) fields.put(key, value.get(key));
                        observed.put(name, fields);
                    }
                }
                text = observed.toString();
            } catch (Exception error) { text = "cached Binder check failed: " + error; }
            finally { request.recycle(); response.recycle(); }
            final String message = text;
            Log.i("MapleSUBinderAdmission", message);
            runOnUiThread(() -> report.setText(message));
        }, "binder-admission-check").start();
    }

    @Override protected void onDestroy() {
        if (bound) unbindService(connection);
        super.onDestroy();
    }
}
