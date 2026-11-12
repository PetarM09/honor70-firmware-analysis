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
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/**
 * Non-exploit validation that ordinary Android apps can use uncontended
 * PI-futex LOCK/UNLOCK from their own UID, rather than only the adb shell.
 *
 * No special permissions, no INTERNET permission, no rooting. The optional
 * requeue check uses deliberately invalid identical addresses; no queue changes.
 */
public final class MainActivity extends Activity {
    static {
        System.loadLibrary("fnepi");
    }
    private static native String runNativeProbe();
    private static native String runRejectedRequeueProbe();

    private TextView output;
    private Button runButton;
    private Button requeueButton;
    private Button profileButton;
    private String report;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int p = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(p, p, p, p);

        TextView title = new TextView(this);
        title.setText("HONOR 70 — C431 Profile Preflight v0.3");
        title.setTextSize(20);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        layout.addView(title);

        TextView warning = new TextView(this);
        warning.setPadding(0, p, 0, p);
        warning.setText("Bez root/EDL i bez aktiviranja GhostLock-a. Prvi test koristi "
                + "LOCK_PI/UNLOCK_PI. Drugi test šalje namerno nevažeći CMP_REQUEUE_PI "
                + "sa istom adresom izvora i odredišta; kernel treba odmah da vrati EINVAL.");
        layout.addView(warning);

        runButton = new Button(this);
        runButton.setText("Proveri PI-futex iz Android aplikacije");
        layout.addView(runButton);

        requeueButton = new Button(this);
        requeueButton.setText("Proveri CMP_REQUEUE_PI rano odbijanje");
        layout.addView(requeueButton);

        profileButton = new Button(this);
        profileButton.setText("Proveri C431 profil bez root-a");
        layout.addView(profileButton);

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
        requeueButton.setOnClickListener(v -> {
            runButton.setEnabled(false);
            requeueButton.setEnabled(false);
            output.setText("Provera ranog odbijanja nevažećeg CMP_REQUEUE_PI poziva...");
            new Thread(() -> {
                String nativeResult;
                try {
                    nativeResult = runRejectedRequeueProbe();
                } catch (Throwable ex) {
                    nativeResult = "NATIVE_ERROR: " + ex.getClass().getSimpleName()
                            + " " + String.valueOf(ex.getMessage());
                }
                final String text = "FNE_PI_GATE_APP_REQUEUE_GUARD_REPORT_V2\n"
                        + deviceDetails() + "\n" + nativeResult
                        + "\nBez čekajućih niti, requeue promene, UAF-a ili root pokušaja.";
                runOnUiThread(() -> {
                    report = text;
                    output.setText(text);
                    runButton.setEnabled(true);
                    requeueButton.setEnabled(true);
                });
            }, "fne-requeue-invalid-guard").start();
        });

        profileButton.setOnClickListener(v -> {
            report = "FNE_C431_PROFILE_PREFLIGHT_V03\n" + deviceDetails()
                    + "\n" + checkBundledProfile()
                    + "\nProvera ne izvršava UAF, requeue, root, EDL ni upis u kernel.";
            output.setText(report);
        });

        copyButton.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager)
                    getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText("FNE PI gate result", report));
            }
        });
    }

    private String checkBundledProfile() {
        try {
            StringBuilder contents = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(getAssets().open("fne-c431-profile.json"),
                            StandardCharsets.UTF_8))) {
                for (String line; (line = reader.readLine()) != null;) {
                    contents.append(line).append('\n');
                }
            }
            JSONObject profile = new JSONObject(contents.toString());
            JSONObject target = profile.getJSONObject("target");
            JSONObject fields = profile.getJSONObject("unresolved_required_fields");
            JSONObject checks = profile.getJSONObject("checks");
            if (profile.getInt("schema_version") != 1
                    || !profile.getString("status").equals("experimental_static_verified_non_executable")
                    || !fields.isNull("kernel_phys_load")
                    || !fields.isNull("reliable_dangling_waiter_lifetime")
                    || checks.getBoolean("exploit_loader_enabled")
                    || checks.getBoolean("active_uaf_trigger_enabled")
                    || checks.getBoolean("kernel_memory_write_enabled")
                    || checks.getBoolean("root_installation_enabled")) {
                return "PROFILE_REJECTED: profil sadrzi nepotvrdjene ili aktivne operacije.";
            }
            String kernel = Os.uname().release;
            String model = Build.MODEL;
            String device = Build.DEVICE;
            int sdk = Build.VERSION.SDK_INT;
            boolean modelOk = model.equals(target.getString("model"));
            boolean deviceOk = device.equals(target.getString("device"));
            boolean kernelOk = kernel.equals(target.getString("kernel_uname_release"));
            boolean sdkOk = sdk == target.getInt("android_sdk");
            boolean all = modelOk && deviceOk && kernelOk && sdkOk;

            return "Profile: " + profile.getString("profile_id")
                    + "\nVersion: " + profile.getString("profile_version")
                    + "\nModel: " + model + " (expected "
                    + target.getString("model") + ") " + (modelOk ? "OK" : "MISMATCH")
                    + "\nDevice: " + device + " (expected "
                    + target.getString("device") + ") " + (deviceOk ? "OK" : "MISMATCH")
                    + "\nKernel: " + kernel + " (expected "
                    + target.getString("kernel_uname_release") + ") " + (kernelOk ? "OK" : "MISMATCH")
                    + "\nAndroid SDK: " + sdk + " (expected "
                    + target.getInt("android_sdk") + ") " + (sdkOk ? "OK" : "MISMATCH")
                    + "\nFirmware build (runtime): " + Build.VERSION.INCREMENTAL
                    + "\nProfile region label: " + target.getString("region")
                    + " (NOT independently attested)"
                    + "\nKernel Image SHA: from offline firmware, NOT checked against running kernel"
                    + "\nUnresolved kernel_phys_load: null"
                    + "\nOutcome: " + (all ? "PROFILE_MODEL_KERNEL_ANDROID_MATCH"
                                                  : "PROFILE_MODEL_KERNEL_ANDROID_MISMATCH")
                    + "\nThis is only a read-only identity preflight, NOT a GhostLock root test.";
        } catch (Exception ex) {
            return "PROFILE_PREFLIGHT_ERROR: " + ex.getClass().getSimpleName()
                    + " " + String.valueOf(ex.getMessage());
        }
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
