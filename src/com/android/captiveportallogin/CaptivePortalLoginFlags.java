/*
 * Copyright (C) 2024 The Android Open Source Project
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

/**
 * Collection of experiment flags used in the CaptivePortalLogin module.
 */
public class CaptivePortalLoginFlags {
    /**
     * Experiment flag to create Android Custom Tabs instead of WebView to display the
     * captive portal when connecting to a network that presents a captive portal.
     */
    public static final String CAPTIVE_PORTAL_CUSTOM_TABS = "captive_portal_custom_tabs";

    /**
     * Experiment flag to use any browser in the system to launch custom tabs temporarily if
     * the default browser doesn't support custom tabs and multi-networking, which is useful
     * for testing.
     */
    public static final String USE_ANY_CUSTOM_TAB_PROVIDER = "use_any_custom_tab_provider";
}
