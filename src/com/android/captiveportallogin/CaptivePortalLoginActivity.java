/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.captiveportallogin;

import static android.net.ConnectivityManager.EXTRA_CAPTIVE_PORTAL_PROBE_SPEC;
import static android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED;

import static com.android.captiveportallogin.CaptivePortalLoginFlags.CAPTIVE_PORTAL_CUSTOM_TABS;
import static com.android.captiveportallogin.DownloadService.isDirectlyOpenType;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.app.admin.DevicePolicyManager;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager.NameNotFoundException;
import android.graphics.Bitmap;
import android.graphics.Insets;
import android.net.CaptivePortal;
import android.net.CaptivePortalData;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.Proxy;
import android.net.Uri;
import android.net.captiveportal.CaptivePortalProbeSpec;
import android.net.http.SslCertificate;
import android.net.http.SslError;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.OutcomeReceiver;
import android.os.ServiceSpecificException;
import android.os.SystemProperties;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.system.OsConstants;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.Log;
import android.util.SparseArray;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.webkit.CookieManager;
import android.webkit.DownloadListener;
import android.webkit.SslErrorHandler;
import android.webkit.URLUtil;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.StringRes;
import androidx.annotation.VisibleForTesting;
import androidx.browser.customtabs.CustomTabsCallback;
import androidx.browser.customtabs.CustomTabsClient;
import androidx.browser.customtabs.CustomTabsIntent;
import androidx.browser.customtabs.CustomTabsServiceConnection;
import androidx.browser.customtabs.CustomTabsSession;
import androidx.core.content.FileProvider;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.android.internal.logging.nano.MetricsProto.MetricsEvent;
import com.android.modules.utils.build.SdkLevel;
import com.android.net.module.util.DeviceConfigUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

public class CaptivePortalLoginActivity extends Activity {
    private static final String TAG = CaptivePortalLoginActivity.class.getSimpleName();
    private static final boolean DBG = true;
    private static final boolean VDBG = false;

    private static final int SOCKET_TIMEOUT_MS = 10000;
    public static final String HTTP_LOCATION_HEADER_NAME = "Location";
    private static final String DEFAULT_CAPTIVE_PORTAL_HTTP_URL =
            "http://connectivitycheck.gstatic.com/generate_204";
    // This should match the FileProvider authority specified in the app manifest.
    private static final String FILE_PROVIDER_AUTHORITY =
            "com.android.captiveportallogin.fileprovider";
    // This should match the path name in the FileProvider paths XML.
    @VisibleForTesting
    static final String FILE_PROVIDER_DOWNLOAD_PATH = "downloads";
    private static final int NO_DIRECTLY_OPEN_TASK_ID = -1;
    private enum Result {
        DISMISSED(MetricsEvent.ACTION_CAPTIVE_PORTAL_LOGIN_RESULT_DISMISSED),
        UNWANTED(MetricsEvent.ACTION_CAPTIVE_PORTAL_LOGIN_RESULT_UNWANTED),
        WANTED_AS_IS(MetricsEvent.ACTION_CAPTIVE_PORTAL_LOGIN_RESULT_WANTED_AS_IS);

        final int metricsEvent;
        Result(int metricsEvent) { this.metricsEvent = metricsEvent; }
    };

    private URL mUrl;
    private CaptivePortalProbeSpec mProbeSpec;
    private String mUserAgent;
    private Network mNetwork;
    private CharSequence mVenueFriendlyName = null;
    @VisibleForTesting
    protected CaptivePortal mCaptivePortal;
    private NetworkCallback mNetworkCallback;
    private ConnectivityManager mCm;
    private DevicePolicyManager mDpm;
    private WifiManager mWifiManager;
    private boolean mLaunchBrowser = false;
    private MyWebViewClient mWebViewClient;
    private SwipeRefreshLayout mSwipeRefreshLayout;
    // This member is just used in the UI thread model(e.g. onCreate and onDestroy), so non-final
    // should be fine.
    private boolean mCaptivePortalCustomTabsEnabled;
    // Ensures that done() happens once exactly, handling concurrent callers with atomic operations.
    private final AtomicBoolean isDone = new AtomicBoolean(false);
    // Must only be touched on the UI thread. This must be initialized to false for thread
    // visibility reasons (if initialized to true, the UI thread may still see false).
    private boolean mIsResumed = false;

    private final CustomTabsCallback mCustomTabsCallback = new CustomTabsCallback() {
        @Override
        public void onNavigationEvent(int navigationEvent, @Nullable Bundle extras) {
            if (navigationEvent == NAVIGATION_STARTED) {
                mCaptivePortal.reevaluateNetwork();
            }
            if (navigationEvent == TAB_HIDDEN) {
                // Run on UI thread to make sure mIsResumed is correctly visible.
                runOnUiThread(() -> {
                    // The tab is hidden when the browser's activity is hidden : screen off,
                    // home button, or press the close button on the tab. In the last case,
                    // close the app. The activity behind the tab is only resumed in that case.
                    if (mIsResumed) done(Result.DISMISSED);
                });
            }
        }
    };

    private final CustomTabsServiceConnection mCustomTabsServiceConnection =
            new CustomTabsServiceConnection() {
                    @Override
                    public void onCustomTabsServiceConnected(@NonNull ComponentName name,
                            @NonNull CustomTabsClient client) {
                        Log.d(TAG, "CustomTabs service connected");
                        final CustomTabsSession session = client.newSession(mCustomTabsCallback);
                        final int availableSpace = findViewById(
                                R.id.custom_tab_header_remaining_space).getHeight();
                        // The application package name that will resolve to the CustomTabs intent
                        // has been set in {@Link CustomTabsIntent.Builder} constructor, unnecessary
                        // to call {@Link Intent#setPackage} to explicitly specify the package name
                        // again.
                        final CustomTabsIntent customTabsIntent =
                                new CustomTabsIntent.Builder(session)
                                        .setNetwork(mNetwork)
                                        .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
                                        // Do not show a title to avoid pages pretend they are part
                                        // of the Android system.
                                        .setShowTitle(false /* showTitle */)
                                        // Have the tab take up the available space under the
                                        // header.
                                        .setInitialActivityHeightPx(availableSpace,
                                                CustomTabsIntent.ACTIVITY_HEIGHT_FIXED)
                                        // Don't show animations, because there is no content to
                                        // animate from or to in this activity. As such, set
                                        // the res IDs to zero, which code for no animation.
                                        .setStartAnimations(CaptivePortalLoginActivity.this,
                                                0, 0)
                                        .setExitAnimations(CaptivePortalLoginActivity.this, 0, 0)
                                        // External handlers will not work since they won't know
                                        // on what network to operate.
                                        .setSendToExternalDefaultHandlerEnabled(false)
                                        // No rounding on the corners so as to have the UI of the
                                        // tab blend more closely with the header contents.
                                        .setToolbarCornerRadiusDp(0)
                                        // Use the identity of the captive portal login app
                                        .setShareIdentityEnabled(true)
                                        // Don't hide the URL bar when scrolling down, to make
                                        // sure the user is always aware they are on the page from
                                        // a captive portal.
                                        .setUrlBarHidingEnabled(false)
                                        .build();

                        // Remove Referrer Header from HTTP probe packet by setting an empty Uri
                        // instance in EXTRA_REFERRER, make sure users using custom tabs have the
                        // same experience as the custom tabs browser.
                        final String emptyReferrer = "";
                        customTabsIntent.intent.putExtra(Intent.EXTRA_REFERRER,
                                Uri.parse(emptyReferrer));
                        customTabsIntent.launchUrl(CaptivePortalLoginActivity.this,
                                Uri.parse(mUrl.toString()));
                    }

                    @Override
                    public void onServiceDisconnected(ComponentName componentName) {
                        Log.d(TAG, "CustomTabs service disconnected");
                    }
            };

    // When starting downloads a file is created via startActivityForResult(ACTION_CREATE_DOCUMENT).
    // This array keeps the download request until the activity result is received. It is keyed by
    // requestCode sent in startActivityForResult.
    @GuardedBy("mDownloadRequests")
    private final SparseArray<DownloadRequest> mDownloadRequests = new SparseArray<>();
    @GuardedBy("mDownloadRequests")
    private int mNextDownloadRequestId = 1;

    // mDownloadService and mDirectlyOpenId must be always updated from the main thread.
    @VisibleForTesting
    int mDirectlyOpenId = NO_DIRECTLY_OPEN_TASK_ID;
    @Nullable
    private DownloadService.DownloadServiceBinder mDownloadService = null;
    private final ServiceConnection mDownloadServiceConn = new ServiceConnection() {
        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.d(TAG, "Download service disconnected");
            mDownloadService = null;
            // Service binding is lost. The spinner for the directly open tasks is no longer
            // needed.
            setProgressSpinnerVisibility(View.GONE);
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            Log.d(TAG, "Download service connected");
            mDownloadService = (DownloadService.DownloadServiceBinder) binder;
            mDownloadService.setProgressCallback(mProgressCallback);
            maybeStartPendingDownloads();
        }
    };

    @Override
    protected void onPause() {
        mIsResumed = false;
        super.onPause();
    }

    @Override
    protected void onResume() {
        mIsResumed = true;
        super.onResume();
    }

    @VisibleForTesting
    final DownloadService.ProgressCallback mProgressCallback =
            new DownloadService.ProgressCallback() {
        @Override
        public void onDownloadComplete(Uri inputFile, String mimeType, int downloadId,
                boolean success) {
            if (isDirectlyOpenType(mimeType) && success) {
                try {
                    startActivity(makeDirectlyOpenIntent(inputFile, mimeType));
                } catch (ActivityNotFoundException e) {
                    // Delete the directly open file if no activity could handle it. This is
                    // verified before downloading, so it should only happen when the handling app
                    // was uninstalled while downloading, which is vanishingly rare. Try to delete
                    // it in case of the target activity being removed somehow.
                    Log.wtf(TAG, "No activity could handle " + mimeType + " file.", e);
                    runOnUiThread(() -> tryDeleteFile(inputFile));
                }
            }

            verifyDownloadIdAndMaybeHideSpinner(downloadId);
        }

        @Override
        public void onDownloadAborted(int downloadId, int reason) {
            if (reason == DownloadService.DOWNLOAD_ABORTED_REASON_FILE_TOO_LARGE) {
                runOnUiThread(() -> Toast.makeText(CaptivePortalLoginActivity.this,
                        R.string.file_too_large_cancel_download, Toast.LENGTH_LONG).show());
            }

            verifyDownloadIdAndMaybeHideSpinner(downloadId);
        }

        private void verifyDownloadIdAndMaybeHideSpinner(int id) {
            // Hide the spinner when the task completed signal for the target task is received.
            //
            // mDirectlyOpenId will not be updated until the existing directly open task is
            // completed or the connection to the DownloadService is lost. If the id is updated to
            // NO_DIRECTLY_OPEN_TASK_ID because of the loss of connection to DownloadService, the
            // spinner should be already hidden. Receiving relevant callback is ignorable.
            runOnUiThread(() -> {
                if (mDirectlyOpenId == id) setProgressSpinnerVisibility(View.GONE);
            });
        }
    };

    @VisibleForTesting
    boolean isFeatureEnabled(final String name) {
        return DeviceConfigUtils.isCaptivePortalLoginFeatureEnabled(getApplicationContext(), name);
    }

    private void maybeStartPendingDownloads() {
        ensureRunningOnMainThread();

        if (mDownloadService == null) return;
        synchronized (mDownloadRequests) {
            for (int i = 0; i < mDownloadRequests.size(); i++) {
                final DownloadRequest req = mDownloadRequests.valueAt(i);
                if (req.mOutFile == null) continue;

                final int dlId = mDownloadService.requestDownload(mNetwork, mUserAgent, req.mUrl,
                        req.mFilename, req.mOutFile, getApplicationContext(), req.mMimeType);
                if (isDirectlyOpenType(req.mMimeType)) {
                    mDirectlyOpenId = dlId;
                    setProgressSpinnerVisibility(View.VISIBLE);
                }

                mDownloadRequests.removeAt(i);
                i--;
            }
        }
    }

    private Intent makeDirectlyOpenIntent(Uri inputFile, String mimeType) {
        return new Intent(Intent.ACTION_VIEW)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                        | Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                .setDataAndType(inputFile, mimeType);
    }

    private void tryDeleteFile(@NonNull Uri file) {
        ensureRunningOnMainThread();
        try {
            DocumentsContract.deleteDocument(getContentResolver(), file);
        } catch (FileNotFoundException e) {
            // Nothing to delete
            Log.wtf(TAG, file + " not found for deleting");
        }
    }

    private static final class DownloadRequest {
        @NonNull final String mUrl;
        @NonNull final String mFilename;
        @NonNull final String mMimeType;
        // mOutFile is null for requests where the device is currently asking the user to pick a
        // place to put the file. When the user has picked the file name, the request will be
        // replaced by a new one with the correct file name in onActivityResult.
        @Nullable final Uri mOutFile;
        DownloadRequest(@NonNull String url, @NonNull String filename, @NonNull String mimeType,
                @Nullable Uri outFile) {
            mUrl = url;
            mFilename = filename;
            mMimeType = mimeType;
            mOutFile = outFile;
        }
    }

    @VisibleForTesting
    @Nullable
    String getDefaultCustomTabsProviderPackage() {
        return CustomTabsClient.getPackageName(getApplicationContext(), null /* packages */);
    }

    @VisibleForTesting
    int getCustomTabsProviderUid(@NonNull final String customTabsProviderPackageName)
            throws NameNotFoundException {
        return getPackageManager().getPackageUid(customTabsProviderPackageName, 0);
    }

    @VisibleForTesting
    boolean isMultiNetworkingSupportedByProvider(@NonNull final String defaultPackageName) {
        return CustomTabsClient.isSetNetworkSupported(getApplicationContext(), defaultPackageName);
    }

    private void applyWindowInsets(final int resourceId) {
        if (!SdkLevel.isAtLeastV()) return;
        final View view = findViewById(resourceId);
        view.setOnApplyWindowInsetsListener((v, windowInsets) -> {
            final Insets insets = windowInsets.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(0 /* left */, insets.top /* top */, 0 /* right */,
                    0 /* bottom */);
            return windowInsets.inset(0, insets.top, 0, 0);
        });
    }

    private void initializeCustomTabHeader() {
        setContentView(R.layout.activity_custom_tab_header);
        // No action bar as this activity implements its own UI instead, so it can display more
        // useful information, e.g. about VPN or private DNS handling.
        getActionBar().hide();
        final TextView headerTitle = findViewById(R.id.custom_tab_header_title);
        headerTitle.setText(getHeaderTitle());
        applyWindowInsets(R.id.custom_tab_header_top_bar);
    }

    private void initializeWebView() {
        // Also initializes proxy system properties.
        mCm.bindProcessToNetwork(mNetwork);

        // Proxy system properties must be initialized before setContentView is called
        // because setContentView initializes the WebView logic which in turn reads the
        // system properties.
        setContentView(R.layout.activity_captive_portal_login);

        getActionBar().setDisplayShowHomeEnabled(false);
        getActionBar().setElevation(0); // remove shadow
        getActionBar().setTitle(getHeaderTitle());
        getActionBar().setSubtitle("");

        applyWindowInsets(R.id.container);

        final WebView webview = getWebview();
        webview.clearCache(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webview, true);
        WebSettings webSettings = webview.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
        webSettings.setUseWideViewPort(true);
        webSettings.setLoadWithOverviewMode(true);
        webSettings.setSupportZoom(true);
        webSettings.setBuiltInZoomControls(true);
        webSettings.setDisplayZoomControls(false);
        webSettings.setDomStorageEnabled(true);
        mWebViewClient = new MyWebViewClient();
        webview.setWebViewClient(mWebViewClient);
        webview.setWebChromeClient(new MyWebChromeClient());
        webview.setDownloadListener(new PortalDownloadListener());
        // Start initial page load so WebView finishes loading proxy settings.
        // Actual load of mUrl is initiated by MyWebViewClient.
        webview.loadData("", "text/html", null);

        mSwipeRefreshLayout = findViewById(R.id.swipe_refresh);
        mSwipeRefreshLayout.setOnRefreshListener(() -> {
            webview.reload();
            mSwipeRefreshLayout.setRefreshing(true);
        });
    }

    private void bindCustomTabsService(@NonNull final String customTabsProviderPackageName) {
        CustomTabsClient.bindCustomTabsService(CaptivePortalLoginActivity.this,
                customTabsProviderPackageName, mCustomTabsServiceConnection);
    }

    @RequiresApi(Build.VERSION_CODES.S)
    private boolean bypassVpnForCustomTabsProvider(
            @NonNull final String customTabsProviderPackageName,
            @NonNull final OutcomeReceiver<Void, ServiceSpecificException> receiver) {
        final Class captivePortalClass = mCaptivePortal.getClass();
        try {
            final Method setDelegateUidMethod =
                    captivePortalClass.getMethod("setDelegateUid", int.class, Executor.class,
                            OutcomeReceiver.class);
            setDelegateUidMethod.invoke(mCaptivePortal,
                    getCustomTabsProviderUid(customTabsProviderPackageName),
                    getMainExecutor(),
                    receiver);
            return true;
        } catch (ReflectiveOperationException | IllegalArgumentException e) {
            Log.e(TAG, "Reflection exception while setting delegate uid", e);
            return false;
        } catch (NameNotFoundException e) {
            Log.e(TAG, "Could not find the UID for " + customTabsProviderPackageName, e);
            return false;
        }
    }

    @Nullable
    private String getCustomTabsProviderPackageIfEnabled() {
        if (!mCaptivePortalCustomTabsEnabled) return null;

        final String defaultPackageName = getDefaultCustomTabsProviderPackage();
        if (defaultPackageName == null) {
            Log.i(TAG, "Default browser doesn't support custom tabs");
            return null;
        }

        final boolean support = isMultiNetworkingSupportedByProvider(defaultPackageName);
        if (!support) {
            Log.i(TAG, "Default browser doesn't support multi-network");
            return null;
        }

        // TODO: b/330670424 - check if privacy settings such as private DNS is bypassable,
        // otherwise, fallback to WebView.
        final LinkProperties lp = mCm.getLinkProperties(mNetwork);
        if (lp == null || lp.getPrivateDnsServerName() != null) {
            Log.i(TAG, "Do not use custom tabs if private DNS (strict mode) is enabled");
            return null;
        }

        return defaultPackageName;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Initialize the feature flag after CaptivePortalLoginActivity is created, otherwise, the
        // context is still null and throw NPE when fetching the package manager from context.
        mCaptivePortalCustomTabsEnabled = isFeatureEnabled(CAPTIVE_PORTAL_CUSTOM_TABS);
        mCaptivePortal = getIntent().getParcelableExtra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL);
        // Null CaptivePortal is unexpected. The following flow will need to access mCaptivePortal
        // to communicate with system. Thus, finish the activity.
        if (mCaptivePortal == null) {
            Log.e(TAG, "Unexpected null CaptivePortal");
            finish();
            return;
        }
        mCm = getSystemService(ConnectivityManager.class);
        mDpm = getSystemService(DevicePolicyManager.class);
        mWifiManager = getSystemService(WifiManager.class);
        mNetwork = getIntent().getParcelableExtra(ConnectivityManager.EXTRA_NETWORK);
        mNetwork = mNetwork.getPrivateDnsBypassingCopy();
        mVenueFriendlyName = getVenueFriendlyName();
        mUserAgent =
                getIntent().getStringExtra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL_USER_AGENT);
        mUrl = getUrl();
        if (mUrl == null) {
            // getUrl() failed to parse the url provided in the intent: bail out in a way that
            // at least provides network access.
            done(Result.WANTED_AS_IS);
            return;
        }
        if (DBG) {
            Log.d(TAG, String.format("onCreate for %s", mUrl));
        }

        final String spec = getIntent().getStringExtra(EXTRA_CAPTIVE_PORTAL_PROBE_SPEC);
        try {
            mProbeSpec = CaptivePortalProbeSpec.parseSpecOrNull(spec);
        } catch (Exception e) {
            // Make extra sure that invalid configurations do not cause crashes
            mProbeSpec = null;
        }

        mNetworkCallback = new NetworkCallback() {
            @Override
            public void onLost(Network lostNetwork) {
                // If the network disappears while the app is up, exit.
                if (mNetwork.equals(lostNetwork)) done(Result.UNWANTED);
            }

            @Override
            public void onCapabilitiesChanged(Network network, NetworkCapabilities nc) {
                handleCapabilitiesChanged(network, nc);
            }
        };
        mCm.registerNetworkCallback(new NetworkRequest.Builder().build(), mNetworkCallback);

        // If the network has disappeared, exit.
        final NetworkCapabilities networkCapabilities = mCm.getNetworkCapabilities(mNetwork);
        if (networkCapabilities == null) {
            finishAndRemoveTask();
            return;
        }

        maybeDeleteDirectlyOpenFile();

        final String customTabsProviderPackageName = getCustomTabsProviderPackageIfEnabled();
        if (customTabsProviderPackageName == null || !SdkLevel.isAtLeastS()) {
            initializeWebView();
        } else {
            initializeCustomTabHeader();
            // TODO: Fall back to WebView iff VPN is enabled and the custom tabs provider is not
            // allowed to bypass VPN, e.g. an error or exception happens when calling the
            // {@link CaptivePortal#setDelegateUid} API. Otherwise, force launch the custom tabs
            // even if VPN cannot be bypassed.
            final boolean success = bypassVpnForCustomTabsProvider(
                    customTabsProviderPackageName,
                    new OutcomeReceiver<Void, ServiceSpecificException>() {
                        // TODO: log the callback result metrics.
                        @Override
                        public void onResult(Void r) {
                            Log.d(TAG, "Set delegate uid for " + customTabsProviderPackageName
                                    + " to bypass VPN successfully");
                            bindCustomTabsService(customTabsProviderPackageName);
                        }
                        @Override
                        public void onError(ServiceSpecificException e) {
                            Log.e(TAG, "Fail to set delegate uid for "
                                    + customTabsProviderPackageName + " to bypass VPN"
                                    + ", error: " + OsConstants.errnoName(e.errorCode), e);
                            bindCustomTabsService(customTabsProviderPackageName);
                        }
                    });
            if (!success) { // caught an exception
                bindCustomTabsService(customTabsProviderPackageName);
            }
        }
    }

    private void maybeDeleteDirectlyOpenFile() {
        // Try to remove the directly open files if exists.
        final File downloadPath = new File(getFilesDir(), FILE_PROVIDER_DOWNLOAD_PATH);
        try {
            deleteRecursively(downloadPath);
        } catch (IOException e) {
            Log.d(TAG, "Exception while deleting temp download files", e);
        }
    }

    private static boolean deleteRecursively(final File path) throws IOException {
        if (path.isDirectory()) {
            final File[] files = path.listFiles();
            if (files != null) {
                for (final File child : files) {
                    deleteRecursively(child);
                }
            }
        }
        final Path parsedPath = Paths.get(path.toURI());
        Log.d(TAG, "Cleaning up " + parsedPath);
        return Files.deleteIfExists(parsedPath);
    }

    @VisibleForTesting
    MyWebViewClient getWebViewClient() {
        return mWebViewClient;
    }

    @VisibleForTesting
    void handleCapabilitiesChanged(@NonNull final Network network,
            @NonNull final NetworkCapabilities nc) {
        if (network.equals(mNetwork) && nc.hasCapability(NET_CAPABILITY_VALIDATED)) {
            // Dismiss when login is no longer needed since network has validated, exit.
            done(Result.DISMISSED);
        }
    }

    // Find WebView's proxy BroadcastReceiver and prompt it to read proxy system properties.
    private void setWebViewProxy() {
        // TODO: migrate to androidx WebView proxy setting API as soon as it is finalized
        try {
            final Field loadedApkField = Application.class.getDeclaredField("mLoadedApk");
            final Class<?> loadedApkClass = loadedApkField.getType();
            final Object loadedApk = loadedApkField.get(getApplication());
            Field receiversField = loadedApkClass.getDeclaredField("mReceivers");
            receiversField.setAccessible(true);
            ArrayMap receivers = (ArrayMap) receiversField.get(loadedApk);
            for (Object receiverMap : receivers.values()) {
                for (Object rec : ((ArrayMap) receiverMap).keySet()) {
                    Class clazz = rec.getClass();
                    if (clazz.getName().contains("ProxyChangeListener")) {
                        Method onReceiveMethod = clazz.getDeclaredMethod("onReceive", Context.class,
                                Intent.class);
                        Intent intent = new Intent(Proxy.PROXY_CHANGE_ACTION);
                        onReceiveMethod.invoke(rec, getApplicationContext(), intent);
                        Log.v(TAG, "Prompting WebView proxy reload.");
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Exception while setting WebView proxy: " + e);
        }
    }

    private void done(Result result) {
        if (isDone.getAndSet(true)) {
            // isDone was already true: done() already called
            return;
        }
        if (DBG) {
            Log.d(TAG, String.format("Result %s for %s", result.name(), mUrl));
        }
        switch (result) {
            case DISMISSED:
                mCaptivePortal.reportCaptivePortalDismissed();
                break;
            case UNWANTED:
                mCaptivePortal.ignoreNetwork();
                break;
            case WANTED_AS_IS:
                mCaptivePortal.useNetwork();
                break;
        }
        finishAndRemoveTask();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.captive_portal_login, menu);
        return true;
    }

    @Override
    public void onBackPressed() {
        final WebView myWebView = findViewById(R.id.webview);
        // The web view is null if the app is using custom tabs
        if (null != myWebView && myWebView.canGoBack() && mWebViewClient.allowBack()) {
            myWebView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        final Result result;
        final String action;
        final int id = item.getItemId();
        // This can't be a switch case because resource will be declared as static only but not
        // static final as of ADT 14 in a library project. See
        // http://tools.android.com/tips/non-constant-fields.
        if (id == R.id.action_use_network) {
            result = Result.WANTED_AS_IS;
            action = "USE_NETWORK";
        } else if (id == R.id.action_do_not_use_network) {
            result = Result.UNWANTED;
            action = "DO_NOT_USE_NETWORK";
        } else {
            return super.onOptionsItemSelected(item);
        }
        if (DBG) {
            Log.d(TAG, String.format("onOptionsItemSelect %s for %s", action, mUrl));
        }
        done(result);
        return true;
    }

    @Override
    public void onStop() {
        super.onStop();
        cancelPendingTask();
    }

    // This must be always called from main thread.
    private void setProgressSpinnerVisibility(int visibility) {
        ensureRunningOnMainThread();

        // getProgressLayout should never return null here, because this method is only ever called
        // when running in webview mode.
        getProgressLayout().setVisibility(visibility);
        if (visibility != View.VISIBLE) {
            mDirectlyOpenId = NO_DIRECTLY_OPEN_TASK_ID;
        }
    }

    @VisibleForTesting
    void cancelPendingTask() {
        ensureRunningOnMainThread();
        if (mDirectlyOpenId != NO_DIRECTLY_OPEN_TASK_ID) {
            Toast.makeText(this, R.string.cancel_pending_downloads, Toast.LENGTH_SHORT).show();
            // Remove the pending task for downloading the directly open file.
            mDownloadService.cancelTask(mDirectlyOpenId);
        }
    }

    private void ensureRunningOnMainThread() {
        if (Looper.getMainLooper().getThread() != Thread.currentThread()) {
            throw new IllegalStateException(
                    "Not running on main thread: " + Thread.currentThread().getName());
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        if (mDownloadService != null) {
            unbindService(mDownloadServiceConn);
        }

        if (mCaptivePortalCustomTabsEnabled) {
            unbindService(mCustomTabsServiceConnection);
        }

        final WebView webview = (WebView) findViewById(R.id.webview);
        if (webview != null) {
            webview.stopLoading();
            webview.setWebViewClient(null);
            webview.setWebChromeClient(null);
            // According to the doc of WebView#destroy(), webview should be removed from the view
            // system before calling the WebView#destroy().
            ((ViewGroup) webview.getParent()).removeView(webview);
            webview.destroy();
        }
        if (mNetworkCallback != null) {
            // mNetworkCallback is not null if mUrl is not null.
            mCm.unregisterNetworkCallback(mNetworkCallback);
        }
        if (mLaunchBrowser) {
            // Give time for this network to become default. After 500ms just proceed.
            for (int i = 0; i < 5; i++) {
                // TODO: This misses when mNetwork underlies a VPN.
                if (mNetwork.equals(mCm.getActiveNetwork())) break;
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                }
            }
            final String url = mUrl.toString();
            if (DBG) {
                Log.d(TAG, "starting activity with intent ACTION_VIEW for " + url);
            }
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode != RESULT_OK || data == null) return;

        // Start download after receiving a created file to download to
        final DownloadRequest pendingRequest;
        synchronized (mDownloadRequests) {
            pendingRequest = mDownloadRequests.get(requestCode);
            if (pendingRequest == null) {
                Log.e(TAG, "No pending download for request " + requestCode);
                return;
            }
        }

        final Uri fileUri = data.getData();
        if (fileUri == null) {
            Log.e(TAG, "No file received from download file creation result");
            return;
        }

        synchronized (mDownloadRequests) {
            // Replace the pending request with file uri in mDownloadRequests.
            mDownloadRequests.put(requestCode, new DownloadRequest(pendingRequest.mUrl,
                    pendingRequest.mFilename, pendingRequest.mMimeType, fileUri));
        }
        maybeStartPendingDownloads();
    }

    private URL getUrl() {
        String url = getIntent().getStringExtra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL_URL);
        if (url == null) { // TODO: Have a metric to know how often empty url happened.
            // ConnectivityManager#getCaptivePortalServerUrl is deprecated starting with Android R.
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.Q) {
                url = DEFAULT_CAPTIVE_PORTAL_HTTP_URL;
            } else {
                url = mCm.getCaptivePortalServerUrl();
            }
        }
        return makeURL(url);
    }

    private static URL makeURL(String url) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            Log.e(TAG, "Invalid URL " + url);
        }
        return null;
    }

    private static String host(URL url) {
        if (url == null) {
            return null;
        }
        return url.getHost();
    }

    private static String sanitizeURL(URL url) {
        // In non-Debug build, only show host to avoid leaking private info.
        return isDebuggable() ? Objects.toString(url) : host(url);
    }

    private static boolean isDebuggable() {
        return SystemProperties.getInt("ro.debuggable", 0) == 1;
    }

    private static boolean isDismissed(
            int httpResponseCode, String locationHeader, CaptivePortalProbeSpec probeSpec) {
        return (probeSpec != null)
                ? probeSpec.getResult(httpResponseCode, locationHeader).isSuccessful()
                : (httpResponseCode == 204);
    }

    @VisibleForTesting
    boolean hasVpnNetwork() {
        for (Network network : mCm.getAllNetworks()) {
            final NetworkCapabilities nc = mCm.getNetworkCapabilities(network);
            if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return true;
            }
        }

        return false;
    }

    @VisibleForTesting
    boolean isAlwaysOnVpnEnabled() {
        final ComponentName cn = new ComponentName(this, CaptivePortalLoginActivity.class);
        return mDpm.isAlwaysOnVpnLockdownEnabled(cn);
    }

    @VisibleForTesting
    class MyWebViewClient extends WebViewClient {
        private static final String INTERNAL_ASSETS = "file:///android_asset/";

        private final String mBrowserBailOutToken = Long.toString(new Random().nextLong());
        private final String mCertificateOutToken = Long.toString(new Random().nextLong());
        // How many Android device-independent-pixels per scaled-pixel
        // dp/sp = (px/sp) / (px/dp) = (1/sp) / (1/dp)
        private final float mDpPerSp = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, 1,
                    getResources().getDisplayMetrics()) /
                    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 1,
                    getResources().getDisplayMetrics());
        private int mPagesLoaded;
        private final ArraySet<String> mMainFrameUrls = new ArraySet<>();

        // If we haven't finished cleaning up the history, don't allow going back.
        public boolean allowBack() {
            return mPagesLoaded > 1;
        }

        private String mSslErrorTitle = null;
        private SslErrorHandler mSslErrorHandler = null;
        private SslError mSslError = null;

        @Override
        public void onPageStarted(WebView view, String urlString, Bitmap favicon) {
            if (urlString.contains(mBrowserBailOutToken)) {
                mLaunchBrowser = true;
                done(Result.WANTED_AS_IS);
                return;
            }
            // The first page load is used only to cause the WebView to
            // fetch the proxy settings.  Don't update the URL bar, and
            // don't check if the captive portal is still there.
            if (mPagesLoaded == 0) {
                return;
            }
            final URL url = makeURL(urlString);
            Log.d(TAG, "onPageStarted: " + sanitizeURL(url));
            // For internally generated pages, leave URL bar listing prior URL as this is the URL
            // the page refers to.
            if (!urlString.startsWith(INTERNAL_ASSETS)) {
                String subtitle = (url != null) ? getHeaderSubtitle(url) : urlString;
                getActionBar().setSubtitle(subtitle);
            }
            // getProgressBar() can't return null here because this method can only be
            // called in webview mode, not in custom tabs mode.
            getProgressBar().setVisibility(View.VISIBLE);
            mCaptivePortal.reevaluateNetwork();
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            mPagesLoaded++;
            // getProgressBar() can't return null here because this method can only be
            // called in webview mode, not in custom tabs mode.
            getProgressBar().setVisibility(View.INVISIBLE);
            mSwipeRefreshLayout.setRefreshing(false);
            if (mPagesLoaded == 1) {
                // Now that WebView has loaded at least one page we know it has read in the proxy
                // settings.  Now prompt the WebView read the Network-specific proxy settings.
                setWebViewProxy();
                // Load the real page.
                view.loadUrl(mUrl.toString());
                return;
            } else if (mPagesLoaded == 2) {
                // Prevent going back to empty first page.
                // Fix for missing focus, see b/62449959 for details. Remove it once we get a
                // newer version of WebView (60.x.y).
                view.requestFocus();
                view.clearHistory();
            }
            mCaptivePortal.reevaluateNetwork();
        }

        // Convert Android scaled-pixels (sp) to HTML size.
        private String sp(int sp) {
            // Convert sp to dp's.
            float dp = sp * mDpPerSp;
            // Apply a scale factor to make things look right.
            dp *= 1.3;
            // Convert dp's to HTML size.
            // HTML px's are scaled just like dp's, so just add "px" suffix.
            return Integer.toString((int)dp) + "px";
        }

        // Check if webview is trying to load the main frame and record its url.
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            final String url = request.getUrl().toString();
            if (request.isForMainFrame()) {
                mMainFrameUrls.add(url);
            }
            // Be careful that two shouldOverrideUrlLoading methods are overridden, but
            // shouldOverrideUrlLoading(WebView view, String url) was deprecated in API level 24.
            // TODO: delete deprecated one ??
            return shouldOverrideUrlLoading(view, url);
        }

        // Record the initial main frame url. This is only called for the initial resource URL, not
        // any subsequent redirect URLs.
        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view,
                WebResourceRequest request) {
            if (request.isForMainFrame()) {
                mMainFrameUrls.add(request.getUrl().toString());
            }
            return null;
        }

        // A web page consisting of a large broken lock icon to indicate SSL failure.
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            final String strErrorUrl = error.getUrl();
            final URL errorUrl = makeURL(strErrorUrl);
            Log.d(TAG, String.format("SSL error: %s, url: %s, certificate: %s",
                    sslErrorName(error), sanitizeURL(errorUrl), error.getCertificate()));
            if (errorUrl == null
                    // Ignore SSL errors coming from subresources by comparing the
                    // main frame urls with SSL error url.
                    || (!mMainFrameUrls.contains(strErrorUrl))) {
                handler.cancel();
                return;
            }
            final String sslErrorPage = makeSslErrorPage();
            view.loadDataWithBaseURL(INTERNAL_ASSETS, sslErrorPage, "text/HTML", "UTF-8", null);
            mSslErrorTitle = view.getTitle() == null ? "" : view.getTitle();
            mSslErrorHandler = handler;
            mSslError = error;
        }

        private String makeHtmlTag() {
            if (getWebview().getLayoutDirection() == View.LAYOUT_DIRECTION_RTL) {
                return "<html dir=\"rtl\">";
            }

            return "<html>";
        }

        // If there is a VPN network or always-on VPN is enabled, there may be no way for user to
        // see the log-in page by browser. So, hide the link which is used to open the browser.
        @VisibleForTesting
        String getVpnMsgOrLinkToBrowser() {
            // Before Android R, CaptivePortalLogin cannot call the isAlwaysOnVpnLockdownEnabled()
            // to get the status of VPN always-on due to permission denied. So adding a version
            // check here to prevent CaptivePortalLogin crashes.
            if (hasVpnNetwork() || isAlwaysOnVpnEnabled()) {
                final String vpnWarning = getString(R.string.no_bypass_error_vpnwarning);
                return "  <div class=vpnwarning>" + vpnWarning + "</div><br>";
            }

            final String continueMsg = getString(R.string.error_continue_via_browser);
            return "  <a id=continue_link href=" + mBrowserBailOutToken + ">" + continueMsg
                    + "</a><br>";
        }

        private String makeErrorPage(@StringRes int warningMsgRes, @StringRes int exampleMsgRes,
                String extraLink) {
            final String warningMsg = getString(warningMsgRes);
            final String exampleMsg = getString(exampleMsgRes);
            return String.join("\n",
                    makeHtmlTag(),
                    "<head>",
                    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                    "  <style>",
                    "    body {",
                    "      background-color:#fafafa;",
                    "      margin:auto;",
                    "      width:80%;",
                    "      margin-top: 96px",
                    "    }",
                    "    img {",
                    "      height:48px;",
                    "      width:48px;",
                    "    }",
                    "    div.warn {",
                    "      font-size:" + sp(16) + ";",
                    "      line-height:1.28;",
                    "      margin-top:16px;",
                    "      opacity:0.87;",
                    "    }",
                    "    div.example, div.vpnwarning {",
                    "      font-size:" + sp(14) + ";",
                    "      line-height:1.21905;",
                    "      margin-top:16px;",
                    "      opacity:0.54;",
                    "    }",
                    "    a {",
                    "      color:#4285F4;",
                    "      display:inline-block;",
                    "      font-size:" + sp(14) + ";",
                    "      font-weight:bold;",
                    "      margin-top:24px;",
                    "      text-decoration:none;",
                    "      text-transform:uppercase;",
                    "    }",
                    "  </style>",
                    "</head>",
                    "<body>",
                    "  <p><img src=quantum_ic_warning_amber_96.png><br>",
                    "  <div class=warn>" + warningMsg + "</div>",
                    "  <div class=example>" + exampleMsg + "</div>",
                    getVpnMsgOrLinkToBrowser(),
                    extraLink,
                    "</body>",
                    "</html>");
        }

        private String makeCustomSchemeErrorPage() {
            return makeErrorPage(R.string.custom_scheme_warning, R.string.custom_scheme_example,
                    "" /* extraLink */);
        }

        private String makeSslErrorPage() {
            final String certificateMsg = getString(R.string.ssl_error_view_certificate);
            return makeErrorPage(R.string.ssl_error_warning, R.string.ssl_error_example,
                    "<a id=cert_link href=" + mCertificateOutToken + ">" + certificateMsg
                            + "</a>");
        }

        @Override
        public boolean shouldOverrideUrlLoading (WebView view, String url) {
            if (url.startsWith("tel:")) {
                return startActivity(Intent.ACTION_DIAL, url);
            } else if (url.startsWith("sms:")) {
                return startActivity(Intent.ACTION_SENDTO, url);
            } else if (!url.startsWith("http:")
                    && !url.startsWith("https:") && !url.startsWith(INTERNAL_ASSETS)) {
                // If the page is not in a supported scheme (HTTP, HTTPS or internal page),
                // show an error page that informs the user that the page is not supported. The
                // user can bypass the warning and reopen the portal in browser if needed.
                // This is done as it is unclear whether third party applications can properly
                // handle multinetwork scenarios, if the scheme refers to a third party application.
                loadCustomSchemeErrorPage(view);
                return true;
            }
            if (url.contains(mCertificateOutToken) && mSslError != null) {
                showSslAlertDialog(mSslErrorHandler, mSslError, mSslErrorTitle);
                return true;
            }
            return false;
        }

        private boolean startActivity(String action, String uriData) {
            final Intent intent = new Intent(action, Uri.parse(uriData));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try {
                CaptivePortalLoginActivity.this.startActivity(intent);
                return true;
            } catch (ActivityNotFoundException e) {
                Log.e(TAG, "No activity found to handle captive portal intent", e);
                return false;
            }
        }

        protected void loadCustomSchemeErrorPage(WebView view) {
            final String errorPage = makeCustomSchemeErrorPage();
            view.loadDataWithBaseURL(INTERNAL_ASSETS, errorPage, "text/HTML", "UTF-8", null);
        }

        private void showSslAlertDialog(SslErrorHandler handler, SslError error, String title) {
            final LayoutInflater factory = LayoutInflater.from(CaptivePortalLoginActivity.this);
            final View sslWarningView = factory.inflate(R.layout.ssl_warning, null);

            // Set Security certificate
            setViewSecurityCertificate(sslWarningView.findViewById(R.id.certificate_layout), error);
            ((TextView) sslWarningView.findViewById(R.id.ssl_error_type))
                    .setText(sslErrorName(error));
            ((TextView) sslWarningView.findViewById(R.id.title)).setText(mSslErrorTitle);
            ((TextView) sslWarningView.findViewById(R.id.address)).setText(error.getUrl());

            AlertDialog sslAlertDialog = new AlertDialog.Builder(CaptivePortalLoginActivity.this)
                    .setTitle(R.string.ssl_security_warning_title)
                    .setView(sslWarningView)
                    .setPositiveButton(R.string.ok, (DialogInterface dialog, int whichButton) -> {
                        // handler.cancel is called via OnCancelListener.
                        dialog.cancel();
                    })
                    .setOnCancelListener((DialogInterface dialogInterface) -> handler.cancel())
                    .create();
            sslAlertDialog.show();
        }

        private void setViewSecurityCertificate(LinearLayout certificateLayout, SslError error) {
            ((TextView) certificateLayout.findViewById(R.id.ssl_error_msg))
                    .setText(sslErrorMessage(error));
            SslCertificate cert = error.getCertificate();
            // TODO: call the method directly once inflateCertificateView is @SystemApi
            try {
                final View certificateView = (View) SslCertificate.class.getMethod(
                        "inflateCertificateView", Context.class)
                        .invoke(cert, CaptivePortalLoginActivity.this);
                certificateLayout.addView(certificateView);
            } catch (ReflectiveOperationException | SecurityException e) {
                Log.e(TAG, "Could not create certificate view", e);
            }
        }
    }

    private class MyWebChromeClient extends WebChromeClient {
        @Override
        public void onProgressChanged(WebView view, int newProgress) {
            // getProgressBar() can't return null here because this method can only be
            // called in webview mode, not in custom tabs mode.
            getProgressBar().setProgress(newProgress);
        }
    }

    private class PortalDownloadListener implements DownloadListener {
        @Override
        public void onDownloadStart(String url, String userAgent, String contentDisposition,
                String mimetype, long contentLength) {
            final String normalizedType = Intent.normalizeMimeType(mimetype);
            // TODO: Need to sanitize the file name.
            final String displayName = URLUtil.guessFileName(
                    url, contentDisposition, normalizedType);

            String guessedMimetype = normalizedType;
            if (TextUtils.isEmpty(guessedMimetype)) {
                guessedMimetype = URLConnection.guessContentTypeFromName(displayName);
            }
            if (TextUtils.isEmpty(guessedMimetype)) {
                guessedMimetype = MediaStore.Downloads.CONTENT_TYPE;
            }

            Log.d(TAG, String.format("Starting download for %s, type %s with display name %s",
                    url, guessedMimetype, displayName));

            final int requestId;
            // WebView should call onDownloadStart from the UI thread, but to be extra-safe as
            // that is not documented behavior, access the download requests array with a lock.
            synchronized (mDownloadRequests) {
                requestId = mNextDownloadRequestId++;
                // Only bind the DownloadService for the first download. The request is put into
                // array later, so size == 0 with null mDownloadService means it's the first item.
                if (mDownloadService == null && mDownloadRequests.size() == 0) {
                    final Intent serviceIntent =
                            new Intent(CaptivePortalLoginActivity.this, DownloadService.class);
                    // To allow downloads to continue while the activity is closed, start service
                    // with a no-op intent, to make sure the service still gets put into started
                    // state.
                    startService(new Intent(getApplicationContext(), DownloadService.class));
                    bindService(serviceIntent, mDownloadServiceConn, Context.BIND_AUTO_CREATE);
                }
            }
            // Skip file picker for directly open MIME type, such as wifi Passpoint configuration
            // files. Fallback to generic design if the download process can not start successfully.
            if (isDirectlyOpenType(guessedMimetype)) {
                try {
                    startDirectlyOpenDownload(url, displayName, guessedMimetype, requestId);
                    return;
                } catch (IOException | ActivityNotFoundException e) {
                    // Fallthrough to show the file picker
                    Log.d(TAG, "Unable to do directly open on the file", e);
                }
            }

            synchronized (mDownloadRequests) {
                // outFile will be assigned after file is created.
                mDownloadRequests.put(requestId, new DownloadRequest(url, displayName,
                        guessedMimetype, null /* outFile */));
            }

            final Intent createFileIntent = DownloadService.makeCreateFileIntent(
                    guessedMimetype, displayName);
            try {
                startActivityForResult(createFileIntent, requestId);
            } catch (ActivityNotFoundException e) {
                // This could happen in theory if the device has no stock document provider (which
                // Android normally requires), or if the user disabled all of them, but
                // should be rare; the download cannot be started as no writeable file can be
                // created.
                Log.e(TAG, "No document provider found to create download file", e);
            }
        }

        private void startDirectlyOpenDownload(String url, String filename, String mimeType,
                int requestId) throws ActivityNotFoundException, IOException {
            ensureRunningOnMainThread();
            // Reject another directly open task if there is one task in progress. Using
            // mDirectlyOpenId here is ok because mDirectlyOpenId will not be updated to
            // non-NO_DIRECTLY_OPEN_TASK_ID until the new task is started.
            if (mDirectlyOpenId != NO_DIRECTLY_OPEN_TASK_ID) {
                Log.d(TAG, "Existing directly open task is in progress. Ignore this.");
                return;
            }

            final File downloadPath = new File(getFilesDir(), FILE_PROVIDER_DOWNLOAD_PATH);
            downloadPath.mkdirs();
            final File file = new File(downloadPath.getPath(), filename);

            final Uri uri = FileProvider.getUriForFile(
                    CaptivePortalLoginActivity.this, getFileProviderAuthority(), file);

            // Test if there is possible activity to handle this directly open file.
            final Intent testIntent = makeDirectlyOpenIntent(uri, mimeType);
            if (getPackageManager().resolveActivity(testIntent, 0 /* flag */) == null) {
                // No available activity is able to handle this.
                throw new ActivityNotFoundException("No available activity is able to handle "
                        + mimeType + " mime type file");
            }

            file.createNewFile();
            synchronized (mDownloadRequests) {
                mDownloadRequests.put(requestId, new DownloadRequest(url, filename, mimeType, uri));
            }

            maybeStartPendingDownloads();
        }
    }

    /**
     * Get the {@link androidx.core.content.FileProvider} authority for storing downloaded files.
     *
     * Useful for tests to override so they can use their own storage directories.
     */
    @VisibleForTesting
    String getFileProviderAuthority() {
        return FILE_PROVIDER_AUTHORITY;
    }

    @Nullable
    private ProgressBar getProgressBar() {
        return findViewById(R.id.progress_bar);
    }

    @Nullable
    private WebView getWebview() {
        return findViewById(R.id.webview);
    }

    @Nullable
    private FrameLayout getProgressLayout() {
        return findViewById(R.id.downloading_panel);
    }

    private String getHeaderTitle() {
        NetworkCapabilities nc = mCm.getNetworkCapabilities(mNetwork);
        final CharSequence networkName = getNetworkName(nc);
        if (TextUtils.isEmpty(networkName)
                || nc == null || !nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return getString(R.string.action_bar_label);
        }
        return getString(R.string.action_bar_title, networkName);
    }

    private CharSequence getNetworkName(NetworkCapabilities nc) {
        // Use the venue friendly name if available
        if (!TextUtils.isEmpty(mVenueFriendlyName)) {
            return mVenueFriendlyName;
        }

        // SSID is only available in NetworkCapabilities from R
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            if (mWifiManager == null) {
                return null;
            }
            final WifiInfo wifiInfo = getWifiConnectionInfo();
            return removeDoubleQuotes(wifiInfo.getSSID());
        }

        if (nc == null) {
            return null;
        }
        return removeDoubleQuotes(nc.getSsid());
    }

    @VisibleForTesting
    WifiInfo getWifiConnectionInfo() {
        return mWifiManager.getConnectionInfo();
    }

    private static String removeDoubleQuotes(String string) {
        if (string == null) return null;
        final int length = string.length();
        if ((length > 1) && (string.charAt(0) == '"') && (string.charAt(length - 1) == '"')) {
            return string.substring(1, length - 1);
        }
        return string;
    }

    private String getHeaderSubtitle(URL url) {
        String host = host(url);
        final String https = "https";
        if (https.equals(url.getProtocol())) {
            return https + "://" + host;
        }
        return host;
    }

    private static final SparseArray<String> SSL_ERRORS = new SparseArray<>();
    static {
        SSL_ERRORS.put(SslError.SSL_NOTYETVALID,  "SSL_NOTYETVALID");
        SSL_ERRORS.put(SslError.SSL_EXPIRED,      "SSL_EXPIRED");
        SSL_ERRORS.put(SslError.SSL_IDMISMATCH,   "SSL_IDMISMATCH");
        SSL_ERRORS.put(SslError.SSL_UNTRUSTED,    "SSL_UNTRUSTED");
        SSL_ERRORS.put(SslError.SSL_DATE_INVALID, "SSL_DATE_INVALID");
        SSL_ERRORS.put(SslError.SSL_INVALID,      "SSL_INVALID");
    }

    private static String sslErrorName(SslError error) {
        return SSL_ERRORS.get(error.getPrimaryError(), "UNKNOWN");
    }

    private static final SparseArray<Integer> SSL_ERROR_MSGS = new SparseArray<>();
    static {
        SSL_ERROR_MSGS.put(SslError.SSL_NOTYETVALID,  R.string.ssl_error_not_yet_valid);
        SSL_ERROR_MSGS.put(SslError.SSL_EXPIRED,      R.string.ssl_error_expired);
        SSL_ERROR_MSGS.put(SslError.SSL_IDMISMATCH,   R.string.ssl_error_mismatch);
        SSL_ERROR_MSGS.put(SslError.SSL_UNTRUSTED,    R.string.ssl_error_untrusted);
        SSL_ERROR_MSGS.put(SslError.SSL_DATE_INVALID, R.string.ssl_error_date_invalid);
        SSL_ERROR_MSGS.put(SslError.SSL_INVALID,      R.string.ssl_error_invalid);
    }

    private static Integer sslErrorMessage(SslError error) {
        return SSL_ERROR_MSGS.get(error.getPrimaryError(), R.string.ssl_error_unknown);
    }

    private CharSequence getVenueFriendlyName() {
        final LinkProperties linkProperties = mCm.getLinkProperties(mNetwork);
        if (linkProperties == null) {
            return null;
        }
        if (linkProperties.getCaptivePortalData() == null) {
            return null;
        }
        final CaptivePortalData captivePortalData = linkProperties.getCaptivePortalData();

        if (captivePortalData == null) {
            return null;
        }

        // TODO: Use CaptivePortalData#getVenueFriendlyName when building with S
        // Use reflection for now
        final Class captivePortalDataClass = captivePortalData.getClass();
        try {
            final Method getVenueFriendlyNameMethod = captivePortalDataClass.getDeclaredMethod(
                    "getVenueFriendlyName");
            return (CharSequence) getVenueFriendlyNameMethod.invoke(captivePortalData);
        } catch (Exception e) {
            // Do nothing
        }
        return null;
    }
}
