// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.fixture;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.os.Build;
import android.os.PersistableBundle;
import android.util.Log;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class ClipboardActivity extends Activity {
    private boolean attempted;

    @Override
    public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (!focused || attempted) return;
        attempted = true;
        File source = new File(getFilesDir(), "fixture-link");
        try {
            String link = new String(Files.readAllBytes(source.toPath()), StandardCharsets.UTF_8);
            ClipData clip = ClipData.newPlainText("Pipe test link", link);
            if (Build.VERSION.SDK_INT >= 33) {
                PersistableBundle extras = new PersistableBundle();
                extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
                clip.getDescription().setExtras(extras);
            }
            getSystemService(ClipboardManager.class).setPrimaryClip(clip);
            Files.delete(source.toPath());
        } catch (IOException | RuntimeException error) {
            Log.e("PipeClipboardFixture", "Could not place the test link on the clipboard");
        } finally {
            finish();
        }
    }
}
