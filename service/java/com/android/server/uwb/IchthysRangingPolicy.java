/*
 * Copyright (C) 2026 The Android Open Source Project
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

package com.android.server.uwb;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.app.role.RoleManager;
import android.content.AttributionSource;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Process;
import android.os.UserHandle;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;

import java.util.List;

/**
 * IchthysOS: UWB ranging is refused by default to ordinary apps.
 *
 * <p>UWB gives centimetre-level distance and angle to nearby devices, which is enough to place
 * the phone inside a room. Holding {@code UWB_RANGING} / {@code RANGING} is therefore not enough
 * on its own: an app must also be named in the per-user {@link Settings.Secure} list
 * {@link #ALLOWED_PACKAGES_SETTING}.
 *
 * <p><b>Who is exempt.</b> Core system UIDs (app ID below {@link Process#FIRST_APPLICATION_UID}),
 * preinstalled apps ({@link ApplicationInfo#FLAG_SYSTEM} / {@link
 * ApplicationInfo#FLAG_UPDATED_SYSTEM_APP}), platform-signed apps and the holders of the standard
 * default-app roles. These are not choices the user is making per app.
 *
 * <p><b>Proxies.</b> Requests reach the UWB stack through an attribution chain — an app calling the
 * Ranging service, or a privileged proxy calling UWB on an app's behalf. Every link in the chain
 * must pass, so a privileged proxy cannot launder a denied app.
 *
 * <p>Enforcement points:
 * <ul>
 *   <li>{@code UwbServiceImpl#openRanging}, after the stock UWB_RANGING check has passed: the
 *       session fails to open ({@code onRangingOpenFailed} with {@code SYSTEM_POLICY}, what a
 *       background app gets on a stock phone). No {@link SecurityException}: the caller holds
 *       the permission, and stock never throws at such a caller.
 *   <li>{@code UwbInjector#checkUwbRangingPermissionForStartDataDelivery}: returns false, the stock
 *       revoked-grant path, so a session that was opened but has not delivered its first result
 *       yet gets no results.
 *   <li>Ranging service {@code UwbAdapter#start}: the UWB technology of a
 *       {@code android.ranging} session closes with the reason the adapter reports for
 *       {@code MISSING_PERMISSION_UWB_RANGING}; other technologies in the session are unaffected.
 *       Both the session's attribution chain and the non-privileged source handed to
 *       {@code start} are checked.
 * </ul>
 *
 * <p>This file is shared with the Ranging service through {@code
 * service-uwb-shared-with-ranging-srcs}, so it only uses SDK/system APIs.
 */
public final class IchthysRangingPolicy {

    private static final String TAG = "IchthysRangingPolicy";

    /**
     * Per-user {@link Settings.Secure} key: comma-separated package names allowed to use UWB
     * ranging. Unset or empty means no third-party app may range. Written by Ichthys Guard.
     */
    public static final String ALLOWED_PACKAGES_SETTING = "ichthys_uwb_pkgs";

    /** Default-app roles whose holders are exempt, matched by name so no SDK level is needed. */
    private static final String[] EXEMPT_ROLES = {
        "android.app.role.ASSISTANT",
        "android.app.role.BROWSER",
        "android.app.role.DIALER",
        "android.app.role.SMS",
        "android.app.role.EMERGENCY",
        "android.app.role.HOME",
        "android.app.role.CALL_REDIRECTION",
        "android.app.role.CALL_SCREENING",
        "android.app.role.WALLET",
        "android.app.role.NOTES",
    };

    private IchthysRangingPolicy() {}

    /**
     * Whether every app in {@code source}'s attribution chain may use UWB ranging. A null source
     * (an internal, system-initiated session) is allowed. Never throws.
     */
    public static boolean isRangingAllowed(@NonNull Context context,
            @Nullable AttributionSource source) {
        AttributionSource current = source;
        while (current != null) {
            if (!isPackageAllowed(context, current.getUid(), current.getPackageName())) {
                Log.i(TAG, "UWB ranging refused for " + current.getPackageName()
                        + " (uid " + current.getUid() + ")");
                return false;
            }
            current = current.getNext();
        }
        return true;
    }

    /** Whether {@code packageName} running as {@code uid} may use UWB ranging. Never throws. */
    public static boolean isPackageAllowed(@NonNull Context context, int uid,
            @Nullable String packageName) {
        if (UserHandle.getAppId(uid) < Process.FIRST_APPLICATION_UID) {
            return true;
        }
        if (TextUtils.isEmpty(packageName)) {
            return false;
        }
        final long token = Binder.clearCallingIdentity();
        try {
            final UserHandle user = UserHandle.getUserHandleForUid(uid);
            final Context userContext = context.createContextAsUser(user, 0);
            if (isExempt(userContext, user, uid, packageName)) {
                return true;
            }
            return isListed(userContext, packageName);
        } catch (RuntimeException e) {
            // Fail closed for third-party apps: an unreadable list grants nothing extra.
            Log.w(TAG, "Failed to evaluate UWB policy for " + packageName, e);
            return false;
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    private static boolean isExempt(Context userContext, UserHandle user, int uid,
            String packageName) {
        final PackageManager pm = userContext.getPackageManager();
        try {
            final ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
            if ((info.flags & (ApplicationInfo.FLAG_SYSTEM
                    | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0) {
                return true;
            }
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
        if (pm.checkSignatures(uid, Process.SYSTEM_UID) == PackageManager.SIGNATURE_MATCH) {
            return true;
        }
        final RoleManager roleManager = userContext.getSystemService(RoleManager.class);
        if (roleManager == null) {
            return false;
        }
        for (String role : EXEMPT_ROLES) {
            try {
                final List<String> holders = roleManager.getRoleHoldersAsUser(role, user);
                if (holders != null && holders.contains(packageName)) {
                    return true;
                }
            } catch (RuntimeException e) {
                // Unknown role on this build, or role service not ready yet.
            }
        }
        return false;
    }

    private static boolean isListed(Context userContext, String packageName) {
        final String value = Settings.Secure.getString(
                userContext.getContentResolver(), ALLOWED_PACKAGES_SETTING);
        if (TextUtils.isEmpty(value)) {
            return false;
        }
        for (String entry : value.split(",")) {
            if (packageName.equals(entry.trim())) {
                return true;
            }
        }
        return false;
    }
}
