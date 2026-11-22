package dev.maplesu.manager.runtime;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/** Keeps the test caller foreground while its independent service exercises su. */
public final class SuLifecycleProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
    }

    @Override public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (hasWindowFocus()) startProbe();
    }

    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (focused) startProbe();
    }

    private void startProbe() {
        Intent intent = getIntent();
        String mode = intent.getStringExtra("mode");
        if (mode != null) {
            intent.removeExtra("mode");
            startService(new Intent(this, SuLifecycleProbeService.class).putExtra("mode", mode));
        }
    }
}
