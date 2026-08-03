<?php
/**
 * ALTCHA protection for the WordPress login form.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether login protection is enabled.
 */
function creationell_captcha_login_enabled(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_login'] );
}

/**
 * Renders the widget inside the login form.
 */
function creationell_captcha_login_render(): void {
    if ( creationell_captcha_login_enabled() ) {
        creationell_captcha_render_widget();
    }
}
add_action( 'login_form', 'creationell_captcha_login_render' );

/**
 * Renders the widget inside `wp_login_form()`-based forms.
 *
 * `wp_login_form()` — used by themes, widgets and shortcodes to embed a
 * login form outside wp-login.php — never fires the `login_form` action
 * above; it runs the `login_form_top`/`login_form_middle`/`login_form_bottom`
 * filters instead. Without this, such a form posted the same `log`/`pwd`/
 * `wp-submit` fields as wp-login.php's own form but never got a widget to
 * solve, so `creationell_captcha_login_verify()` below rejected even correct
 * credentials (IN-6).
 *
 * @param string $content Existing middle-of-form markup.
 * @return string
 */
function creationell_captcha_login_form_middle( string $content ): string {
    if ( ! creationell_captcha_login_enabled() ) {
        return $content;
    }

    return $content . creationell_captcha_build_widget_markup();
}
add_filter( 'login_form_middle', 'creationell_captcha_login_form_middle' );

/**
 * Whether the current request is an interactive, browser-submitted login
 * attempt — as opposed to XML-RPC, REST/Application-Passwords, AJAX or a
 * programmatic `wp_signon()` call made by other code.
 *
 * Deliberately does NOT use `isset( $_POST['wp-submit'] )` as the signal
 * (IN-1): wp-login.php's own login handler calls `wp_signon()`
 * unconditionally, regardless of whether "wp-submit" was posted, so an
 * attacker posting directly to wp-login.php could simply omit it and skip
 * the captcha entirely. The `log`/`pwd` field pair is what both
 * wp-login.php's own form and `wp_login_form()`-based theme forms actually
 * send. WooCommerce's My-Account login form uses different field names
 * (`username`/`password`) and is intentionally NOT matched here — it has
 * its own toggle/verification pair (`protect_wc_login`, see IN-7).
 */
function creationell_captcha_login_is_interactive(): bool {
    // CLI / cron / WP-CLI / XML-RPC never post a browser login form —
    // consistent with the interceptor's own non-interactive guard.
    if ( 'cli' === php_sapi_name()
        || ( defined( 'WP_CLI' ) && WP_CLI )
        || ( defined( 'DOING_CRON' ) && DOING_CRON )
        || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
    ) {
        return false;
    }

    // Genuine REST requests (incl. Application Passwords, which authenticate
    // via "determine_current_user" rather than "authenticate") set this
    // constant themselves inside WordPress core's own rest_api_loaded() —
    // trustworthy precisely because core sets it, not request input.
    //
    // Deliberately NOT checked here: $_GET['rest_route'] (in any form,
    // isset() or !empty()). wp-login.php is a standalone entry point that
    // never calls parse_request()/wp(), so it never triggers
    // rest_api_loaded() no matter what the query string contains — the
    // parameter is completely inert there. Treating its mere presence as
    // "this is REST" reopened IN-1/IN-8: an attacker could append
    // "?rest_route=" to a raw POST against wp-login.php and skip
    // verification again, confirmed live in review. Same value-independent-
    // existence-check anti-pattern already flagged as BK-1 for the
    // interceptor (class-interceptor.php) — do not repeat it here.
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        return false;
    }

    // AJAX-driven programmatic logins are not the browser login form either
    // — consistent with the interceptor auto-inject's own AJAX exemption.
    if ( wp_doing_ajax() ) {
        return false;
    }

    // Only wp-login.php is ever the genuine POST target of an interactive
    // browser login: WordPress core hardcodes wp_login_form()'s <form
    // action> to site_url( 'wp-login.php', 'login_post' ), and wp-login.php's
    // own form obviously posts to itself. Gating on the entry script — not
    // just on field names — keeps a third-party login form that happens to
    // reuse "log"/"pwd" but posts to its own REST/AJAX/admin-post handler
    // (which never gets our widget rendered either, since that only happens
    // via the `login_form` action or the `login_form_middle` filter) from
    // being wrongly required to solve a captcha it was never shown.
    // $GLOBALS['pagenow'] is set by WordPress core itself in wp-settings.php
    // from the actually executing script, before any plugin code runs, so it
    // cannot be spoofed via request input the way a query parameter can;
    // URL-masking plugins that legitimately proxy to wp-login.php (e.g. WP
    // Defender's "Mask Login", confirmed in this project's test
    // environment) explicitly preserve it as 'wp-login.php' for exactly this
    // reason before requiring the real file.
    if ( 'wp-login.php' !== ( $GLOBALS['pagenow'] ?? '' ) ) {
        return false;
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no nonce exists prior to authentication; presence check only.
    return isset( $_POST['log'] ) && isset( $_POST['pwd'] );
}

/**
 * Verifies the captcha during an interactive login.
 *
 * @param WP_User|WP_Error|null $user     Authenticated user or error.
 * @param string                $username Submitted username.
 * @param string                $password Submitted password.
 * @return WP_User|WP_Error|null
 */
function creationell_captcha_login_verify( $user, $username, $password ) {
    if ( ! creationell_captcha_login_enabled() ) {
        return $user;
    }

    if ( ! creationell_captcha_login_is_interactive() ) {
        return $user;
    }
    if ( '' === (string) $username || '' === (string) $password ) {
        return $user;
    }

    // Deliberately does NOT return early when $user is already a WP_Error
    // (e.g. a wrong password rejected at priority 20 by
    // wp_authenticate_username_password()) — IN-8: skipping the captcha
    // check on failed credentials made brute-forcing passwords free, and a
    // wrong password is exactly the attempt IN-1 let straight through anyway.

    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        do_action(
            'creationell_captcha_event',
            'verified',
            [
                'plugin' => 'WordPress',
                'action' => 'login',
                'reason' => $bypass['reason'],
            ]
        );
        return $user;
    }

    if ( ! creationell_captcha_verify_request() ) {
        do_action(
            'creationell_captcha_event',
            'failed',
            [
                'plugin' => 'WordPress',
                'action' => 'login',
                'reason' => __( 'Challenge ungültig oder fehlend', 'creationell-captcha' ),
            ]
        );

        return new WP_Error(
            'creationell_captcha_failed',
            __( '<strong>Fehler:</strong> Die Sicherheitsabfrage wurde nicht bestanden.', 'creationell-captcha' )
        );
    }

    do_action(
        'creationell_captcha_event',
        'verified',
        [
            'plugin' => 'WordPress',
            'action' => 'login',
        ]
    );

    return $user;
}
add_filter( 'authenticate', 'creationell_captcha_login_verify', 30, 3 );
