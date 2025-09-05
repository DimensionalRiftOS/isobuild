/**
 * Dimensional Rift Hardened Firefox - user.js
 * 
 * This file contains primary security and privacy hardening settings
 * for the browser. This is where most hardening settings should be placed.
 * 
 * These settings are inspired by Tor Browser and
 * optimized to create minimal issues in daily usage.
 */

// ===== Telemetry and Data Collection Protection =====
// Disable all telemetry and data collection features to maximize privacy

// Prevent data submission to Mozilla
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.firstRunURL", "");
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.pioneer-new-studies-available", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("beacon.enabled", false);
user_pref("browser.uitour.enabled", false);
user_pref("browser.uitour.url", "");

// Disable studies and experiments
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

// Disable crash reporter
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

// ===== Disable Mozilla and Third-Party Integrations =====
// Disable Pocket
user_pref("extensions.pocket.enabled", false);

// Disable Mozilla accounts
user_pref("identity.fxaccounts.enabled", false);

// Disable Firefox Sync
user_pref("services.sync.enabled", false);
user_pref("identity.sync.tokenserver.uri", "");

// Disable access to Firefox Sync server
user_pref("services.sync.serverURL", "");

// Disable form autofill and browser history suggestions
user_pref("browser.formfill.enable", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("extensions.formautofill.heuristics.enabled", false);

// Disable password manager
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);

// Disable addon recommendations but allow updates
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);
// Note: app.update.auto is locked as false in 00securonis.js
// Keeping extensions update enabled but respecting system update settings
user_pref("extensions.update.enabled", true);
user_pref("extensions.update.autoUpdateDefault", true);

// ===== HTTPS and TLS Hardening =====
// HTTPS-only mode disabled for I2P compatibility (many I2P sites use HTTP)
user_pref("dom.security.https_only_mode", false);
user_pref("dom.security.https_only_mode.upgrade_local", false);
user_pref("dom.security.https_only_mode.onion", false);
user_pref("dom.security.https_only_mode_pbm", false);

// Disable TLS 1.0 and 1.1 (keep TLS 1.2 and 1.3 only)
user_pref("security.tls.version.min", 3);
user_pref("security.tls.version.max", 4);

// OCSP hardening - must staple
user_pref("security.ssl.enable_ocsp_must_staple", true);
user_pref("security.OCSP.require", true);

// Disable insecure passive content
user_pref("security.mixed_content.block_display_content", true);
user_pref("security.mixed_content.block_object_subrequest", true);

// Disable insecure downloads from secure sites
user_pref("dom.block_download_insecure", true);

// Disable TLS Session Tickets
user_pref("security.ssl.disable_session_identifiers", true);

// Strict TLS negotiations
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("security.ssl.require_safe_negotiation", true);

// ===== Privacy and Tracking Protection =====
// First-Party Isolation (already set in 00securonis.js)
user_pref("privacy.firstparty.isolate.restrict_opener_access", true);

// Tracking Protection
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.pbmode.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.donottrackheader.value", 1);

// Enhanced Tracking Protection (strict)
user_pref("browser.contentblocking.category", "strict");
user_pref("browser.contentblocking.features.strict", "tp,tpPrivate,cookieBehavior5,cookieBehaviorPBM5,cm,fp,stp");

// ===== Comprehensive Browser Fingerprinting Protections =====
user_pref("privacy.resistFingerprinting", true);                // Main fingerprinting resistance
user_pref("privacy.resistFingerprinting.letterboxing", false);  // Disable letterboxing for usability
user_pref("privacy.fingerprintingProtection.enabled", true);    // Additional fingerprinting protection
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true); // Prevent fingerprinting via add-on detection
user_pref("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", true); // Auto-decline canvas access
user_pref("privacy.resistFingerprinting.randomization.daily_reset", true); // Daily reset of randomization
user_pref("privacy.resistFingerprinting.randomization.enabled", true); // Enable randomization
user_pref("privacy.resistFingerprinting.randomDataOnCanvasExtract", true); // Randomize canvas extraction
user_pref("privacy.reduceTimerPrecision", true); // Reduce timer precision
user_pref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 1000); // Set microsecond precision
// Value 0 is set later in the file for better fingerprinting protection
user_pref("device.sensors.enabled", false);                     // Disable device sensors
user_pref("geo.enabled", false);                               // Disable geolocation
user_pref("webgl.disabled", false);                            // Enable WebGL for site compatibility

// Canvas fingerprint protection
user_pref("privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts", true); // Auto-decline canvas access
user_pref("canvas.capturestream.enabled", false);                // Disable canvas capture stream

// ===== WebRTC Protection =====
// Keep WebRTC enabled but with maximum security
user_pref("media.peerconnection.enabled", true);                // Keep WebRTC but with protections
user_pref("media.peerconnection.ice.relay_only", false);       // Allow srflx/relay (TURN-only can break calls)
user_pref("media.peerconnection.ice.default_address_only", true); // Use default route only
user_pref("media.peerconnection.ice.no_host", true);           // Disable host ICE candidates
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true); // Use proxy when available

// ===== Network Settings =====
// Prefetching settings modified for better I2P performance
user_pref("network.dns.disablePrefetch", false);                // Enable DNS prefetching for I2P
user_pref("network.dns.disablePrefetchFromHTTPS", false);       // Enable DNS prefetching from HTTPS for I2P
user_pref("network.predictor.enabled", true);                  // Enable network prediction for I2P
user_pref("network.predictor.enable-prefetch", true);          // Enable prefetch for I2P
user_pref("network.prefetch-next", true);                      // Enable link prefetching for I2P
user_pref("network.http.speculative-parallel-limit", 6);        // Enable speculative connections
user_pref("browser.urlbar.speculativeConnect.enabled", true);  // Enable speculative connections from URL bar

// Disable DNS over HTTPS (preventing Cloudflare DNS)
user_pref("network.trr.mode", 5);                              // Disable DNS over HTTPS
user_pref("network.trr.uri", "");                              // Clear DoH URI
user_pref("network.trr.bootstrapAddress", "");                // Clear DoH bootstrap address
user_pref("network.trr.default_provider_uri", "");            // Clear DoH provider URI

// ===== Advanced Network Isolation =====
user_pref("privacy.partition.network_state", true);               // Network state partitioning
user_pref("privacy.partition.always_partition_third_party_non_cookie_storage", true);  // Partition 3rd party storage
user_pref("privacy.partition.serviceWorkers", true);              // Service Worker isolation
user_pref("privacy.storagePrincipal.enabledForTrackers", true);   // Storage isolation for trackers

// ===== Cookie and Storage Improvements =====
user_pref("privacy.sanitize.sanitizeOnShutdown", true);           // Clean on shutdown
user_pref("privacy.clearOnShutdown.offlineApps", false);          // Keep offline application data
user_pref("privacy.clearOnShutdown.siteSettings", false);         // Preserve site settings (for usability)
user_pref("privacy.sanitize.timeSpan", 0);                        // Clear all history

// ===== HTTP Security Headers =====
user_pref("network.http.referer.XOriginPolicy", 2);               // Limit referer information to same origin
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);       // Trim cross-origin referer header to domain
user_pref("network.http.referer.defaultPolicy.trackers", 1);      // Limit referer sending to trackers
user_pref("network.http.referer.defaultPolicy.pbmode", 1);        // Limit referer to trackers in private mode

// ===== Hardware Information Leak Protection =====
user_pref("media.navigator.mediacapabilities.enabled", false);     // Hide media capabilities
user_pref("dom.gamepad.enabled", false);                          // Disable gamepad API
user_pref("media.mediasource.enabled", true);                     // Keep Media Source Extensions enabled (for video)
user_pref("dom.w3c_touch_events.enabled", 0);                     // Disable touch screen API

// ===== DOM Security Improvements =====
user_pref("dom.targetBlankNoOpener.enabled", true);               // Apply noopener for target=_blank
user_pref("dom.popup_allowed_events", "click dblclick");          // Only allow popups on click events
user_pref("dom.disable_window_move_resize", true);                // Prevent window size/position changes
user_pref("dom.allow_scripts_to_close_windows", false);           // Prevent scripts from closing windows

// ===== Cache and Storage Limitations =====
user_pref("browser.sessionstore.privacy_level", 2);               // Session storage privacy (maximum)
user_pref("browser.sessionstore.interval", 30000);                // Session save interval (seconds)
user_pref("browser.sessionhistory.max_entries", 10);              // Keep fewer page history entries
user_pref("browser.sessionhistory.max_total_viewers", 4);         // Number of cached pages

// ===== Security Improvements =====
user_pref("security.tls.version.fallback-limit", 4);              // TLS fallback limit: TLS 1.3
user_pref("security.cert_pinning.enforcement_level", 2);          // Certificate pinning mandatory
user_pref("security.pki.sha1_enforcement_level", 1);              // Don't allow SHA-1 certificates
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);            // Disable weak cipher suite
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);            // Disable weak cipher suite

// ===== Privacy Improvements =====
user_pref("browser.link.open_newwindow.restriction", 0);          // Restrict new window opening
user_pref("permissions.default.geo", 2);                          // Deny location sharing by default
user_pref("permissions.default.camera", 2);                       // Deny camera access by default
user_pref("permissions.default.microphone", 2);                   // Deny microphone access by default
user_pref("permissions.default.desktop-notification", 2);         // Deny notifications by default
user_pref("permissions.default.xr", 2);                           // Deny VR access by default

// ===== JavaScript Security Balanced Settings =====
// Note: JIT engines are enabled for better web performance
// Comment these out if you need maximum security but reduced performance
// user_pref("javascript.options.wasm_baselinejit", false);
// user_pref("javascript.options.ion", false);
// user_pref("javascript.options.asmjs", false);
// user_pref("javascript.options.baselinejit", false);

// Alternative safer approach with better performance
user_pref("javascript.options.jit.content", true);               // Keep content JIT enabled
user_pref("javascript.options.jit.chrome", false);               // Disable UI JIT (security improvement)
user_pref("javascript.options.wasm_caching", false);             // Disable WASM caching for security

// ===== Tor Browser-like Additional Settings =====
user_pref("network.captive-portal-service.enabled", false);       // Disable captive portal detection
user_pref("network.connectivity-service.enabled", false);         // Disable connectivity checking
user_pref("network.dns.disableIPv6", false);                      // Enable IPv6 DNS for I2P compatibility
user_pref("network.IDN_show_punycode", true);                     // Show punycode (URL phishing protection)

// ===== Cache Improvements =====
user_pref("browser.cache.memory.capacity", 524288);             // Increase memory cache (512MB)
user_pref("browser.cache.memory.max_entry_size", 51200);        // Increase maximum cache entry size
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true); // Force media cache in RAM

// ===== Preferences - For Better Usability =====
user_pref("accessibility.blockautorefresh", false);                // Block auto-refresh
user_pref("browser.backspace_action", 2);                         // Don't use backspace as back navigation
user_pref("browser.tabs.warnOnClose", false);                     // Disable warning when closing multiple tabs
user_pref("browser.tabs.warnOnCloseOtherTabs", false);            // Disable warning when closing other tabs
user_pref("full-screen-api.warning.delay", 0);                    // Remove fullscreen warning delay
user_pref("full-screen-api.warning.timeout", 0);                  // Remove fullscreen warning timeout
user_pref("security.warn_about_mime_changes", false);            // Disable MIME type warnings
user_pref("security.warn_viewing_mixed", false);                 // Disable mixed content warnings
user_pref("security.dialog_enable_delay", 0);                    // Remove delay for security dialogs
user_pref("browser.xul.error_pages.enabled", true);              // Enable built-in error pages
user_pref("network.http.prompt-temp-redirect", false);           // Disable prompts for temporary redirects
user_pref("security.insecure_connection_text.enabled", false);   // Disable insecure connection warnings
// Disable bookmarks toolbar and warnings
user_pref("browser.toolbars.bookmarks.visibility", "never");      // Never show bookmarks toolbar
user_pref("browser.bookmarks.restore_default_bookmarks", false);  // Don't restore default bookmarks
user_pref("browser.bookmarks.showMobileBookmarks", false);       // Don't show mobile bookmarks
user_pref("browser.bookmarks.autoExportHTML", false);           // Don't auto-export bookmarks
user_pref("browser.bookmarks.max_backups", 0);                  // No bookmark backups

// ===== Safe Browsing Privacy =====
// Disable Google Safe Browsing and phishing protection to prevent data sharing with Google
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.url", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");

// ===== Cookie and Storage Policies =====
// Default daily usage configuration - allows cookies with tracking protection
user_pref("network.cookie.cookieBehavior", 5);                    // Total Cookie Protection (site-partitioned)
user_pref("network.cookie.lifetimePolicy", 0);                    // Accept cookies normally (persist)
user_pref("network.cookie.thirdparty.sessionOnly", true);         // Clear third-party cookies on session end
user_pref("network.cookie.thirdparty.nonsecureSessionOnly", true); // Still limit insecure third-party cookies to session

// Cookie partitioning settings
// privacy.partition.network_state already set above

// ===== Cache Settings - Daily Mode =====
user_pref("browser.cache.disk.capacity", 1024000);                // Enable disk cache (1GB)
user_pref("browser.cache.disk.enable", true);                    // Enable disk cache
user_pref("browser.cache.disk.smart_size.enabled", true);        // Enable smart sizing of cache

// ===== DuckDuckGo Search Integration =====
// Set DuckDuckGo as default search engine
user_pref("browser.search.defaultenginename", "DuckDuckGo");
user_pref("browser.search.defaultenginename.US", "DuckDuckGo");
user_pref("browser.search.defaulturl", "https://duckduckgo.com/");
user_pref("keyword.URL", "https://duckduckgo.com/");

// I2P-Only URL Settings - No clearnet URLs
user_pref("browser.newtab.url", "about:blank");
user_pref("browser.search.hiddenOneOffs", "Google,Amazon.com,Bing,Yahoo,eBay,Twitter");

// ===== Theme Support Settings =====
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true); // default is false
user_pref("svg.context-properties.content.enabled", true);

// ===== Add-on Settings =====
user_pref("extensions.autoDisableScopes", 0);
user_pref("extensions.enabledScopes", 5);
user_pref("extensions.installDistroAddons", true);
user_pref("xpinstall.signatures.required", false);
// Prevent extensions from opening their pages after installation
user_pref("extensions.ui.notifyHidden", true);
user_pref("extensions.webextensions.restrictedDomains", "accounts-static.cdn.mozilla.net,accounts.firefox.com,addons.cdn.mozilla.net,addons.mozilla.org,api.accounts.firefox.com,content.cdn.mozilla.net,discovery.addons.mozilla.org,install.mozilla.org,oauth.accounts.firefox.com,profile.accounts.firefox.com,support.mozilla.org,sync.services.mozilla.com");
user_pref("browser.startup.upgradeDialog.enabled", false);
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.getAddons.cache.enabled", false);
// Allow extension update checks but disable recommendations
user_pref("extensions.getAddons.link.url", "https://addons.mozilla.org/%LOCALE%/firefox/");
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);

// ===== Performance Optimizations =====
user_pref("network.http.max-connections", 900);                 // Increase max connections
user_pref("network.http.max-persistent-connections-per-server", 10); // Increase per-server connections
user_pref("network.http.max-urgent-start-excessive-connections-per-host", 5); // Allow more urgent connections
user_pref("network.http.pacing.requests.enabled", false);       // Disable request pacing
user_pref("security.ssl.enable_ocsp_stapling", true);          // Enable OCSP stapling

// Adjust some strict security settings for better performance
// Note: These settings conflict with stricter settings defined elsewhere
// Using the stricter settings for better security

// ===== Additional Privacy & Security Improvements =====
// Prevent accessibility services from accessing your browser
user_pref("accessibility.force_disabled", 1);

// Disable WebGL debugging and developer tools
user_pref("webgl.disable-debug-renderer-info", true);
user_pref("webgl.enable-debug-renderer-info", false);

// Enhanced referrer control
user_pref("network.http.referer.spoofSource", true);
user_pref("network.http.sendRefererHeader", 1);

// Disable clipboard events and notifications
user_pref("dom.event.clipboardevents.enabled", false);

// Enhanced media protection
user_pref("media.eme.enabled", false);

// Disable site reading installed plugins
user_pref("plugins.enumerable_names", "");

// Disable domain guessing
user_pref("browser.fixup.alternate.enabled", false);

// Disable search suggestions
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);

// Disable face detection
user_pref("camera.control.face_detection.enabled", false);

// Disable reading battery status
user_pref("dom.battery.enabled", false);

// Disable keyboard fingerprinting
user_pref("dom.keyboardevent.code.enabled", false);

// Disable network information API
user_pref("dom.netinfo.enabled", false);

// Disable site reading installed themes
user_pref("devtools.chrome.enabled", false);

// Disable WebAssembly
user_pref("javascript.options.wasm", true);

// Additional Storage Protection
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.pagethumbnails.capturing_disabled", true);

// Disable Firefox account features
user_pref("identity.fxaccounts.commands.enabled", false);

// Enhanced SSL/TLS Security
user_pref("security.tls.enable_0rtt_data", false);

// Disable dormant tabs feature
user_pref("browser.tabs.unloadOnLowMemory", false);

// Additional tracking protection (already defined above)
// user_pref("privacy.trackingprotection.socialtracking.enabled", true);
// user_pref("privacy.trackingprotection.fingerprinting.enabled", true);

// I2P-Only startup and homepage settings (CONSOLIDATED)
user_pref("browser.startup.page", 0);                           // Blank page on startup - no clearnet access
user_pref("browser.startup.homepage", "about:blank");           // Blank homepage - no clearnet access
user_pref("browser.newtabpage.enabled", false);                 // Disable new tab page completely
user_pref("browser.newtab.preload", false);                     // Don't preload new tab content
user_pref("browser.newtabpage.activity-stream.default.sites", ""); // No default sites
user_pref("browser.newtabpage.pinned", "[]");                   // No pinned sites
user_pref("browser.startup.firstrunSkipsHomepage", true);        // Skip first-run homepage
user_pref("browser.newtabpage.activity-stream.prerender", false); // No prerendering
user_pref("browser.newtabpage.activity-stream.showSearch", false); // No search on new tab
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false); // No top sites
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false); // No top stories
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false); // No snippets
user_pref("browser.newtabpage.topSitesRows", 0);                 // No top sites rows
user_pref("browser.newtabpage.directory.source", "");            // No directory source
user_pref("browser.newtabpage.directory.ping", "");              // No directory ping
user_pref("browser.startup.homepage_override.mstone", "ignore"); // Ignore milestone overrides
user_pref("browser.startup.homepage_override.buildID", "");      // No build ID override

// ===== Additional Hardening Without Breaking Usability =====

// Enhanced SSL/TLS Security
user_pref("security.tls.enable_0rtt_data", false);              // Disable 0-RTT to prevent replay attacks
user_pref("security.family_safety.mode", 0);                    // Disable Windows Family Safety cert store

// Enhanced Content Security (I2P Compatible)
// NOTE: Mixed content blocking disabled for I2P compatibility (set later in file)
user_pref("security.csp.enable", true);                         // Enable CSP
user_pref("security.dialog_enable_delay", 0);                   // No delay for security dialogs (usability)
// Block data URLs to prevent bypasses
user_pref("security.data_uri.block_toplevel_data_uri_navigations", true);
user_pref("security.fileuri.strict_origin_policy", true);       // Strict file URI policy

// Additional Privacy Protections
// privacy.firstparty.isolate.restrict_opener_access already set above
// privacy.resistFingerprinting.letterboxing already set above
user_pref("privacy.window.name.update.enabled", true);          // Clear window.name on domain change
user_pref("privacy.clearOnShutdown.cookies", false);           // Keep cookies between sessions
user_pref("privacy.clearOnShutdown.formdata", false);          // Keep form data
user_pref("privacy.clearOnShutdown.sessions", false);        // Keep sessions for usability
user_pref("privacy.sanitize.sanitizeOnShutdown", true);        // Enable sanitize on shutdown

// Enhanced DOM Security (I2P Compatible)
user_pref("dom.security.https_only_mode_send_http_background_request", false);
user_pref("dom.security.https_only_mode_error_page_user_suggestions", false); // Disable clearnet suggestions
// dom.event.contextmenu.enabled already set above
// dom.disable_window_move_resize already set above
// dom.popup_allowed_events already set above
user_pref("dom.disable_beforeunload", false);                    // Disable "Leave Page" popups
user_pref("dom.disable_open_during_load", true);                // Prevent automatic window opening
user_pref("dom.push.connection.enabled", false);                // Disable push notifications
user_pref("dom.webnotifications.enabled", false);               // Disable web notifications

// Additional Network Security
user_pref("network.auth.subresource-http-auth-allow", 1);       // Strict HTTP authentication
// HTTP referrer settings already defined above
// network.proxy.socks_remote_dns already set below
user_pref("network.security.esni.enabled", true);               // Enable Encrypted SNI if available

// WebRTC Hardening - settings already defined in WebRTC Protection section above

// Enhanced Extension Security
// extensions.webextensions.restrictedDomains already set above
// extensions.enabledScopes already set above
user_pref("extensions.webextensions.protocol.remote", false);    // Disable remote protocol handlers
user_pref("extensions.webextensions.userScripts.enabled", false); // Disable user scripts

// Additional Fingerprinting Resistance
// webgl.disabled already set above (enabled for compatibility)
// canvas.capturestream.enabled already set above
user_pref("media.webspeech.synth.enabled", false);              // Disable speech synthesis
user_pref("media.webspeech.recognition.enable", false);         // Disable speech recognition
// device.sensors.enabled already set above
user_pref("browser.zoom.siteSpecific", false);                  // Disable per-site zoom
user_pref("dom.webaudio.enabled", false);                       // Disable Web Audio API

// Remove security dialog delay as it's annoying
// security.dialog_enable_delay already set above

// ===== Window Size and Display Settings =====
user_pref("privacy.resistFingerprinting.letterboxing", false);  // Disable letterboxing (which can make windows small)
user_pref("browser.window.width", 1280);                       // Set default window width
user_pref("browser.window.height", 900);                       // Set default window height
// REMOVED DUPLICATE: Window size already set above

// ===== I2P Startup Configuration (REMOVED DUPLICATES) =====
// All startup settings consolidated above in homepage section
// Note: browser.tabs.inTitlebar is already set in 00securonis.js
// user_pref("browser.tabs.inTitlebar", 1);                       // Show tabs in titlebar for more space

// ===== Privacy - Clear Data on Shutdown (I2P Optimized) =====
// I2P privacy settings - clear traces but keep functionality
user_pref("privacy.clearOnShutdown.cache", true);            // Clear cache
user_pref("privacy.clearOnShutdown.cookies", false);         // Keep necessary cookies
user_pref("privacy.clearOnShutdown.downloads", false);       // Keep downloads list
user_pref("privacy.clearOnShutdown.formdata", true);         // Clear form data for privacy
user_pref("privacy.clearOnShutdown.history", true);          // Clear history for privacy
user_pref("privacy.clearOnShutdown.offlineApps", true);      // Clear offline data
user_pref("privacy.clearOnShutdown.sessions", true);         // Clear sessions - start fresh
user_pref("privacy.clearOnShutdown.siteSettings", false);    // Keep site settings
user_pref("privacy.sanitize.sanitizeOnShutdown", true);      // Enable sanitize on shutdown

// Session handling (I2P Privacy Mode)
user_pref("browser.sessionstore.privacy_level", 2);          // Store minimal session data
user_pref("browser.sessionstore.interval", 30000);           // Session save interval
user_pref("browser.sessionstore.max_tabs_undo", 10);         // Allow undo of recently closed tabs
user_pref("browser.sessionstore.resume_from_crash", false);  // Don't restore - privacy first
user_pref("browser.sessionstore.resume_session_once", false); // Never restore sessions
user_pref("browser.sessionstore.max_resumed_crashes", 0);    // No auto-restore

// Cookie and Storage Restrictions
user_pref("network.cookie.lifetimePolicy", 0);               // Accept cookies normally (persist)
user_pref("network.cookie.thirdparty.sessionOnly", true);    // Clear third-party cookies on session end
user_pref("browser.cache.disk.enable", true);                // Enable disk cache for performance
user_pref("browser.cache.memory.enable", true);              // Keep memory cache for performance
user_pref("browser.cache.memory.capacity", 524288);          // 512MB memory cache

// ===== I2P Network Configuration =====
// I2P HTTP/HTTPS proxy settings - OPTIMIZED FOR I2P ACCESS
user_pref("network.proxy.type", 1);                          // Manual proxy configuration
user_pref("network.proxy.http", "127.0.0.1");               // I2P HTTP proxy
user_pref("network.proxy.http_port", 4444);                  // I2P HTTP proxy port
user_pref("network.proxy.ssl", "127.0.0.1");                // I2P HTTPS proxy
user_pref("network.proxy.ssl_port", 4445);                   // I2P HTTPS proxy port
user_pref("network.proxy.share_proxy_settings", true);       // Use same proxy for all protocols
user_pref("network.proxy.socks_remote_dns", false);           // Don't force DNS through proxy for better compatibility
user_pref("network.proxy.no_proxies_on", "localhost,127.0.0.1,aus5.mozilla.org,download.mozilla.org,addons.mozilla.org,blocklists.settings.services.mozilla.com,firefox.settings.services.mozilla.com,push.services.mozilla.com,shavar.services.mozilla.com,updates.addons.mozilla.org,versioncheck.addons.mozilla.org,normandy.cdn.mozilla.net,content-signature.cdn.mozilla.net,remote-settings.cdn.mozilla.net"); // Allow direct access to local and Mozilla update servers
user_pref("network.security.ports.banned", "");              // Don't restrict any ports

// ===== I2P ACCESS SETTINGS =====
// Allow I2P domains while blocking clearnet for privacy
user_pref("network.dns.blockDotCom", false);                  // Allow .com domains for compatibility
user_pref("network.dns.blockDotNet", false);                  // Allow .net domains for compatibility
user_pref("network.dns.blockDotOrg", false);                  // Allow .org domains for compatibility
user_pref("extensions.blocklist.enabled", true);            // Enable blocklist for security

// Allow common TLDs for better compatibility
user_pref("network.dns.blockDotInfo", false);                 // Allow .info domains
user_pref("network.dns.blockDotBiz", false);                  // Allow .biz domains
user_pref("network.dns.blockDotEdu", false);                  // Allow .edu domains
user_pref("network.dns.blockDotGov", false);                  // Allow .gov domains
user_pref("network.dns.blockDotMil", false);                  // Allow .mil domains

// Force all DNS through I2P proxy
user_pref("network.proxy.socks_remote_dns", true);           // Force DNS through proxy
user_pref("network.dns.disableIPv6", false);                 // Enable IPv6 for I2P compatibility
user_pref("network.proxy.failover_direct", false);           // Never failover to direct connection
user_pref("network.proxy.allow_hijacking_localhost", false);  // Don't allow localhost hijacking

// Content Security Policy to block clearnet
user_pref("security.csp.enable", true);
user_pref("security.csp.experimentalEnabled", true);

// I2P and Tor domain compatibility
user_pref("network.dns.blockDotOnion", false);               // Allow .onion domains (Tor compatibility)
// HTTPS-only mode already disabled above for I2P compatibility
// Mixed content settings for I2P sites (many use HTTP)
user_pref("security.mixed_content.block_active_content", false); // Allow mixed content for I2P
user_pref("security.mixed_content.block_display_content", false); // Allow mixed content display
user_pref("security.mixed_content.upgrade_display_content", false); // Don't upgrade display content

// ===== Search and Privacy Configuration =====
// DuckDuckGo as default search engine
user_pref("browser.search.defaultenginename", "DuckDuckGo");
user_pref("browser.search.selectedEngine", "DuckDuckGo");
user_pref("browser.urlbar.placeholderName", "DuckDuckGo");

// Privacy-focused browsing
user_pref("browser.search.suggest.enabled", false);          // Disable search suggestions
user_pref("browser.urlbar.suggest.searches", false);         // Disable URL bar search suggestions
user_pref("browser.urlbar.suggest.history", false);          // Disable history suggestions
user_pref("browser.urlbar.suggest.openpage", false);         // Disable open page suggestions
user_pref("browser.formfill.enable", false);                 // Disable form history
user_pref("browser.urlbar.maxRichResults", 5);               // Limit URL bar results

// Enhanced privacy protection for I2P browsing
user_pref("network.cookie.cookieBehavior", 1);               // Block third-party cookies
user_pref("privacy.firstparty.isolate", true);               // First-party isolation
user_pref("privacy.trackingprotection.enabled", true);       // Enable tracking protection
user_pref("privacy.trackingprotection.cryptomining.enabled", true); // Block cryptominers
user_pref("privacy.trackingprotection.fingerprinting.enabled", true); // Block fingerprinting

// ===== Secondary Tor Support =====
// Note: To switch to Tor, change network.proxy.type to 2 and use PAC file
// PAC file location: file:///etc/rift/onion.pac
// Tor SOCKS proxy: 127.0.0.1:9050

// Enhanced Tor-style protections
user_pref("privacy.resistFingerprinting.randomDataOnCanvasExtract", true);
user_pref("privacy.resistFingerprinting.randomization.daily_reset", true);
user_pref("privacy.reduceTimerPrecision", true);
user_pref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 1000);

// Strengthen WebRTC protection
user_pref("media.peerconnection.ice.relay_only", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);

// Additional network protection
user_pref("network.protocol-handler.external.data", false);
user_pref("network.protocol-handler.external.guest", false);
user_pref("network.protocol-handler.external.javascript", false);

// Enhanced device fingerprinting protection
user_pref("dom.battery.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("dom.vibrator.enabled", false);
user_pref("dom.w3c_touch_events.enabled", 0);

// Font fingerprinting protection (comment out if breaks important sites)
user_pref("browser.display.use_document_fonts", 1);

// ===== Additional Settings from 00cyrethium.js =====
// Basic system and update settings - UPDATES ENABLED
user_pref("app.update.enabled", true);
user_pref("app.update.auto", true);
user_pref("app.update.mode", 1);
user_pref("app.update.service.enabled", true);
user_pref("browser.shell.checkDefaultBrowser", false);

// Network and connectivity settings - I2P ONLY MODE (REMOVED DUPLICATE)
user_pref("network.manage-offline-status", false);
// DISABLED: Tor PAC file - using I2P only
// user_pref("network.proxy.autoconfig_url", "file:///etc/rift/onion.pac");
// DISABLED: Tor SOCKS proxy - using I2P HTTP proxy only
// user_pref("network.proxy.socks", "127.0.0.1");
// user_pref("network.proxy.socks_port", 9050);
// NOTE: network.proxy.type already set above in I2P configuration section

// UI and theme settings
user_pref("browser.urlbar.trimURLs", false);
user_pref("browser.tabs.inTitlebar", 1);
user_pref("devtools.theme", "dark");
user_pref("browser.theme.toolbar-theme", 0);
user_pref("extensions.activeThemeID", "firefox-compact-dark@mozilla.org");
user_pref("browser.rights.3.shown", true);
// UI customization state - toolbar layout (removed bookmarks and incognito icons)
user_pref("browser.uiCustomization.state", "{\"placements\":{\"widget-overflow-fixed-list\":[],\"nav-bar\":[\"back-button\",\"forward-button\",\"home-button\",\"stop-reload-button\",\"urlbar-container\",\"save-to-pocket-button\",\"downloads-button\",\"fxa-toolbar-menu-button\",\"ublock0_raymondhill_net-browser-action\",\"developer-button\"],\"toolbar-menubar\":[\"menubar-items\"],\"TabsToolbar\":[\"tabbrowser-tabs\",\"new-tab-button\",\"alltabs-button\"],\"PersonalToolbar\":[]},\"seen\":[\"save-to-pocket-button\",\"developer-button\",\"ublock0_raymondhill_net-browser-action\"],\"dirtyAreaCache\":[\"nav-bar\",\"PersonalToolbar\"],\"currentVersion\":17,\"newElementCount\":5}");

// Extension settings
// extensions.getAddons.cache.enabled already set above
// extensions.htmlaboutaddons.inline-options.enabled already set above
// browser.messaging-system.whatsNewPanel.enabled already set above

// ===== Extended Telemetry Protection =====
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry.structuredIngestion", false);
user_pref("browser.newtabpage.activity-stream.telemetry.structuredIngestion.endpoint", "");
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.urlbar.eventTelemetry.enabled", false);
user_pref("security.app_menu.recordEventTelemetry", false);
user_pref("security.identitypopup.recordEventTelemetry", false);
user_pref("security.certerrors.recordEventTelemetry", false);
user_pref("security.protectionspopup.recordEventTelemetry", false);
user_pref("security.xfocsp.errorReporting.enabled", false);
user_pref("toolkit.telemetry.ecosystemtelemetry.enabled", false);
user_pref("toolkit.telemetry.cachedClientID", 0);
user_pref("services.sync.telemetry.maxPayloadCount", 0);
user_pref("datareporting.healthreport.service.enabled", false);

// ===== Additional Privacy Settings =====
user_pref("media.video_stats.enabled", false);
user_pref("plugins.notifyMissingFlash", false);

// Additional tracking protection
// privacy.trackingprotection.pbmode.enabled already set above
user_pref("privacy.trackingprotection.origin_telemetry.enabled", true);

// Cookie behavior settings
user_pref("network.cookie.cookieBehavior.pbmode", 5);

// Locale and region settings
user_pref("javascript.use_us_english_locale", true);
user_pref("browser.search.region", "US");
user_pref("browser.region.update.enabled", false);
user_pref("browser.region.update.region", "");

// WebGL settings
// webgl.enable-debug-renderer-info already set above

// Search engine settings
user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "DuckDuckGo");
user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.searchEngines", "DuckDuckGo");
user_pref("browser.policies.runOncePerModification.setDefaultSearchEngine", "DuckDuckGo");
user_pref("browser.search.isUS", false);
user_pref("browser.search.official", false);
user_pref("browser.search.update", false);

// New tab page activity stream settings
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("extensions.pocket.onSaveRecs", false);
user_pref("extensions.pocket.showHome", false);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("browser.newtabpage.activity-stream.asrouter.useRemoteL10n", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.newtabpage.activity-stream.discoverystream.enabled", false);
user_pref("browser.newtabpage.activity-stream.discoverystream.isCollectionDismissible", false);
user_pref("browser.newtabpage.activity-stream.discoverystream.spocs.personalized", false);
user_pref("browser.newtabpage.activity-stream.feeds.aboutpreferences", false);
user_pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", false);
user_pref("browser.newtabpage.activity-stream.feeds.favicon", false);
user_pref("browser.newtabpage.activity-stream.feeds.newtabinit", false);
user_pref("browser.newtabpage.activity-stream.feeds.places", false);
user_pref("browser.newtabpage.activity-stream.feeds.prefs", false);
user_pref("browser.newtabpage.activity-stream.feeds.recommendationproviderswitcher", false);
user_pref("browser.newtabpage.activity-stream.feeds.sections", false);
user_pref("browser.newtabpage.activity-stream.feeds.system.topsites", true);
user_pref("browser.newtabpage.activity-stream.feeds.system.topstories", false);
user_pref("browser.newtabpage.activity-stream.feeds.systemtick", false);
user_pref("browser.newtabpage.activity-stream.improvesearch.handoffToAwesomebar", false);
user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);
user_pref("browser.newtabpage.activity-stream.newNewtabExperience.enabled", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeBookmarks", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeDownloads", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeVisited", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

// ===== I2P DOMAIN WHITELIST CONFIGURATION =====
// Custom domain filtering - only allow .i2p domains
user_pref("network.protocol-handler.expose-all", false);
user_pref("network.protocol-handler.expose.http", true);
user_pref("network.protocol-handler.expose.https", true);
user_pref("network.protocol-handler.expose.ftp", false);
user_pref("network.protocol-handler.external.http", false);
user_pref("network.protocol-handler.external.https", false);

// Additional clearnet blocking measures
user_pref("network.dns.localDomains", "i2p");              // Only resolve .i2p domains locally
user_pref("network.automatic-ntlm-auth.trusted-uris", "");  // Clear trusted URIs
user_pref("network.negotiate-auth.trusted-uris", "");       // Clear negotiation URIs

// Disable Mozilla services except updates
user_pref("services.blocklist.update_enabled", true);  // Allow blocklist updates for security
user_pref("services.blocklist.signing.enforced", true); // Keep blocklist signing for security
// Extension updates allowed via default Mozilla URLs
// user_pref("extensions.update.url", "");  // REMOVED - allow addon updates
user_pref("extensions.webservice.discoverURL", "");
user_pref("browser.safebrowsing.downloads.remote.url", "");

// Block search engine updates and suggestions
user_pref("browser.search.update", false);
user_pref("browser.search.geoSpecificDefaults", false);
user_pref("browser.search.geoip.url", "");

// Disable captive portal and connectivity checks
user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("network.connectivity-service.IPv4.url", "");
user_pref("network.connectivity-service.IPv6.url", "");

// ===== REMOVED DUPLICATE SETTINGS =====
// Homepage and new tab settings already consolidated above

// Block most clearnet connections except Mozilla updates
// user_pref("app.update.url", "");  // REMOVED - allow Firefox updates
// user_pref("app.update.url.manual", "");  // REMOVED - allow manual update checks
// user_pref("app.update.url.details", "");  // REMOVED - allow update details
user_pref("browser.geolocation.warning.infoURL", "");
user_pref("browser.xor.warning.infoURL", "");

// Additional clearnet connection blocking
user_pref("network.dns.offline-localhost", false);           // Don't resolve localhost when offline
user_pref("network.http.use-cache", true);                   // Use cache to avoid external requests
user_pref("network.http.proxy.respect-be-conservative", true); // Be conservative with proxy usage
user_pref("network.stricttransportsecurity.preloadlist", false); // Disable HSTS preload list
user_pref("security.remote_settings.crlite_filters.enabled", false); // Disable remote CRL filters
user_pref("security.remote_settings.intermediates.enabled", false); // Disable remote intermediate certs

// Configure WebRTC for I2P compatibility
user_pref("media.peerconnection.enabled", true);            // Enable WebRTC for I2P services
user_pref("media.peerconnection.turn.disable", false);        // Enable TURN servers for I2P
user_pref("media.peerconnection.use_document_iceservers", true); // Use document ICE servers
user_pref("media.peerconnection.identity.enabled", true);   // Enable WebRTC identity

// Disable all Mozilla telemetry endpoints
user_pref("toolkit.telemetry.server_owner", "");             // Clear telemetry owner
user_pref("toolkit.telemetry.cachedClientID", "");           // Clear client ID
user_pref("datareporting.healthreport.documentServerURI", ""); // Clear health report URI
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", false);

// Enhanced DNS security for I2P-only
user_pref("network.trr.excluded-domains", "i2p,onion");       // Only exclude I2P and onion from DoH
user_pref("network.trr.skip-AAAA-when-not-supported", true); // Skip IPv6 when not supported
user_pref("network.dns.upgrade_with_https_rr", false);       // Don't upgrade DNS with HTTPS RR

// === WARNING MESSAGE FOR I2P-ONLY MODE ===
// This browser is configured for I2P-ONLY access
// Only .i2p and .onion domains will be accessible
// All clearnet domains and connections are blocked EXCEPT:
// - Mozilla update servers (for Firefox and addon security updates)
// - Mozilla blocklist servers (for malware protection)
// WebRTC is completely disabled to prevent IP leaks
// DNS is forced through I2P proxy to prevent leaks
// 
// SECURITY NOTE: Mozilla update servers bypass I2P proxy to prevent
// exploit risk from outdated browser/addons. This is essential for security.