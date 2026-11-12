package org.openhonor.fnepigate;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.system.Os;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * Non-exploit validation that ordinary Android apps can use uncontended
 * PI-futex LOCK/UNLOCK from their own UID, rather than only the adb shell.
 *
 * No special permissions, no INTERNET permission, no rooting and no requeue.
 */
public final class MainActivity extends Activity {
    static {
        System.loadLibrary("fnepi");
    }
    private static native String runNativeProbe();

    private TextView output;
    private Button runButton;
    private String report;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int p = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(p, p, p, p);

        TextView title = new TextView(this);
        title.setText("HONOR 70 — PI-Futex Application Gate");
        title.setTextSize(20);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        layout.addView(title);

        TextView warning = new TextView(this);
        warning.setPadding(0, p, 0, p);
        warning.setText("Ovaj test NE koristi GhostLock ranjivost, requeue, root ili EDL. "
                + "Radi samo LOCK_PI/UNLOCK_PI nad jednom sopstvenom promenljivom.");
        layout.addView(warning);

        runButton = new Button(this);
        runButton.setText("Proveri PI-futex iz Android aplikacije");
        layout.addView(runButton);

        Button copyButton = new Button(this);
        copyButton.setText("Kopiraj rezultat");
        layout.addView(copyButton);

        ScrollView scroller = new ScrollView(this);
        output = new TextView(this);
        output.setTextSize(13);
        output.setTextIsSelectable(true);
        scroller.addView(output);
        layout.addView(scroller, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(layout);

        report = "Provera nije pokrenuta.\n\n" + deviceDetails()
                + "\nDijagnostika radi kao pravi instalirani Android app proces.";
        output.setText(report);

        runButton.setOnClickListener(v -> {
            runButton.setEnabled(false);
            output.setText("Izvršavanje bezopasnog nekontendiranog PI-futex testa…");
            new Thread(() -> {
                String nativeResult;
                try {
                    nativeResult = runNativeProbe();
                } catch (Throwable ex) {
                    nativeResult = "NATIVE_ERROR: " + ex.getClass().getSimpleName()
                            + " " + String.valueOf(ex.getMessage());
                }
                final String text = "FNE_PI_GATE_APP_REPORT_V1\n"
                        + deviceDetails() + "\n" + nativeResult
                        + "\nNije testiran GhostLock requeue/UAF ni root.";
                runOnUiThread(() -> {
                    report = text;
                    output.setText(text);
                    runButton.setEnabled(true);
                });
            }, "fne-pi-gate").start();
        });
        copyButton.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager)
                    getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText("FNE PI gate result", report));
            }
        });
    }

    private static String readFirstLine(String path) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line = br.readLine();
            return line == null ? "not_available" : line.trim();
        } catch (IOException | SecurityException ex) {
            return "not_available (" + ex.getClass().getSimpleName() + ")";
        }
    }

    private static String processStatus() {
        StringBuilder status = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/status"))) {
            for (String line; (line = br.readLine()) != null; ) {
                if (line.startsWith("Seccomp:")
                        || line.startsWith("Seccomp_filters:")
                        || line.startsWith("NoNewPrivs:")
                        || line.startsWith("CapEff:")) {
                    status.append(line).append('\n');
                }
            }
        } catch (IOException | SecurityException ex) {
            status.append("Process status not available: ").append(
                    ex.getClass().getSimpleName()).append('\n');
        }
        return status.toString();
    }

    private static String deviceDetails() {
        String uname;
        try {
            uname = Os.uname().release;
        } catch (Throwable ex) {
            uname = "not_available";
        }
        return "Model: " + Build.MODEL
                + "\nDevice: " + Build.DEVICE
                + "\nKernel: " + uname
                + "\nAndroid SDK: " + Build.VERSION.SDK_INT
                + "\nApp UID: " + Process.myUid()
                + "\nSELinux context: " + readFirstLine("/proc/self/attr/current")
                + "\n" + processStatus();
    }
}
