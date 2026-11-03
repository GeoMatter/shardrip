package com.geomatter.shardrip;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.webkit.ConsoleMessage;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shardrip for Android: runs the same Python Shardrip as the desktop version and shows
 * its phone-friendly interface. Everything stays on the phone (127.0.0.1) - no browser.
 */
public class MainActivity extends Activity {
    static final String TAG = "Shardrip";
    private static final int REQ_CAMERA = 1, REQ_FILE = 2, REQ_START = 3;
    private static final Pattern LINK = Pattern.compile("https?://\\S+", Pattern.CASE_INSENSITIVE);

    private WebView web;
    private String appUrl;
    private String pendingLink;
    private boolean pageReady;
    private ValueCallback<Uri[]> fileCallback;
    private PermissionRequest pendingCamera;
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        web = new WebView(this);
        web.setBackgroundColor(0xFF0A0F1A);
        setContentView(web);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setAllowFileAccess(false);

        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                Uri u = req.getUrl();
                if ("127.0.0.1".equals(u.getHost())) return false;
                try {  // any other link (e.g. GitHub) opens in the normal browser
                    startActivity(new Intent(Intent.ACTION_VIEW, u));
                } catch (ActivityNotFoundException ignored) { }
                return true;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                if (url != null && url.startsWith("http://127.0.0.1")) {
                    pageReady = true;
                    deliverLink();
                }
            }
        });

        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onPermissionRequest(PermissionRequest req) {
                // The page asks for the camera (QR scanner) - grant it once Android allows it.
                runOnUiThread(() -> {
                    boolean wantsCamera = false;
                    for (String r : req.getResources())
                        if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(r)) wantsCamera = true;
                    if (!wantsCamera) { req.deny(); return; }
                    if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                        req.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                    } else {
                        pendingCamera = req;
                        requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA);
                    }
                });
            }

            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> cb, FileChooserParams params) {
                // "Upload QR image" - pick a screenshot/photo
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = cb;
                try {
                    startActivityForResult(params.createIntent(), REQ_FILE);
                } catch (ActivityNotFoundException e) {
                    fileCallback = null;
                    return false;
                }
                return true;
            }

            @Override
            public boolean onConsoleMessage(ConsoleMessage m) {
                Log.i(TAG, "page: " + m.message());
                return true;
            }
        });

        web.loadDataWithBaseURL(null, "<html><body style='background:#0a0f1a;color:#8ea3bf;font-family:sans-serif;"
                + "display:flex;align-items:center;justify-content:center;height:90vh'>⚡ Starting Shardrip…</body></html>",
                "text/html", "utf-8", null);

        takeLink(getIntent());
        askStartupPermissions();
        startShardrip();
    }

    private void askStartupPermissions() {
        List<String> want = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            want.add(Manifest.permission.POST_NOTIFICATIONS);  // the "Downloading…" notification
        if (Build.VERSION.SDK_INT <= 28
                && checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED)
            want.add(Manifest.permission.WRITE_EXTERNAL_STORAGE);  // saving to Download/ on old Android
        if (!want.isEmpty()) requestPermissions(want.toArray(new String[0]), REQ_START);
    }

    private void startShardrip() {
        new Thread(() -> {
            try {
                if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
                File dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                //noinspection ResultOfMethodCallIgnored
                dl.mkdirs();
                PyObject mod = Python.getInstance().getModule("shardrip_android");
                String url = mod.callAttr("start", dl.getAbsolutePath()).toString();
                Log.i(TAG, "SHARDRIP_URL " + url);
                runOnUiThread(() -> { appUrl = url; web.loadUrl(url); });
                handler.post(watchDownloads);
            } catch (Throwable t) {
                Log.e(TAG, "Shardrip failed to start", t);
                String msg = String.valueOf(t.getMessage()).replace("<", "&lt;");
                runOnUiThread(() -> web.loadDataWithBaseURL(null,
                        "<html><body style='background:#0a0f1a;color:#ff6b6b;font-family:sans-serif;padding:24px'>"
                                + "<h3>Shardrip couldn't start</h3><pre style='white-space:pre-wrap'>" + msg
                                + "</pre></body></html>", "text/html", "utf-8", null));
            }
        }, "shardrip-start").start();
    }

    /** While a download runs, keep a foreground service (notification) so Android doesn't kill it. */
    private final Runnable watchDownloads = new Runnable() {
        @Override
        public void run() {
            try {
                boolean busy = Python.getInstance().getModule("shardrip_android").callAttr("busy").toBoolean();
                if (busy && !DownloadService.running) {
                    Intent i = new Intent(MainActivity.this, DownloadService.class);
                    if (Build.VERSION.SDK_INT >= 26) startForegroundService(i); else startService(i);
                }
            } catch (Throwable t) {
                Log.w(TAG, "watch: " + t);
            }
            handler.postDelayed(this, 1500);
        }
    };

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        takeLink(intent);
        deliverLink();
    }

    /** A link shared to Shardrip from another app (WhatsApp, Chrome…). */
    private void takeLink(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) return;
        String text = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (text == null) return;
        Matcher m = LINK.matcher(text);
        if (m.find()) pendingLink = m.group();
    }

    private void deliverLink() {
        if (pendingLink == null || !pageReady) return;
        String js = "useScanned(" + JSONObject.quote(pendingLink) + ")";
        pendingLink = null;
        web.evaluateJavascript(js, null);
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        if (code == REQ_CAMERA && pendingCamera != null) {
            if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED)
                pendingCamera.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
            else
                pendingCamera.deny();
            pendingCamera = null;
        }
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        if (code == REQ_FILE && fileCallback != null) {
            fileCallback.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data));
            fileCallback = null;
            return;
        }
        super.onActivityResult(code, result, data);
    }

    @Override
    public void onBackPressed() {
        // Keep Shardrip (and any download) running in the background instead of closing it.
        moveTaskToBack(true);
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacks(watchDownloads);
        super.onDestroy();
    }
}
