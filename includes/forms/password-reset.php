<?php
/**
 * ALTCHA protection for the WordPress password-reset (lost password) form.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether password-reset protection is enabled.
 */
function creationell_captcha_password_reset_enabled(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_password_reset'] );
}

/**
 * Renders the widget inside the lost-password form.
 */
function creationell_captcha_password_reset_render(): void {
    if ( creationell_captcha_password_reset_enabled() ) {
        creationell_captcha_render_widget();
    }
}
add_action( 'lostpassword_form', 'creationell_captcha_password_reset_render' );

/**
 * Why the current request is not a public lost-password form submission.
 *
 * `lostpassword_post` is NOT a form hook. WordPress core fires it inside
 * `retrieve_password()` (wp-includes/user.php), and that function is also the
 * back end of every administrative and programmatic reset:
 * `wp_ajax_send_password_reset()` behind the "Send reset link" button on
 * user-edit.php, the "Send password reset" bulk action in wp-admin/users.php,
 * and any WP-CLI or third-party plugin call. None of those ever renders our
 * widget, so demanding a solved challenge there rejected the request with
 * "Die Sicherheitsabfrage wurde nicht bestanden" and no mail was ever sent —
 * `retrieve_password()` bails out before dispatch once `$errors` is non-empty.
 *
 * Returns the reason rather than a bare bool for two reasons: the caller logs
 * it on the `verified` event exactly like a bypass reason, and every branch
 * stays individually observable in the regression test. Under the CLI SAPI a
 * bool predicate could only ever show its CLI branch — which is why the
 * administrative branch is checked FIRST here, before the non-interactive
 * ones. In production the order is immaterial: WP-CLI has neither `is_admin()`
 * nor a current user, so it can never take the administrative branch.
 *
 * @return string|null Exemption reason, or null for a genuine form submission.
 */
function creationell_captcha_password_reset_exempt_reason(): ?string {
    // Administrative resets. Both admin entry points run their own nonce and
    // capability checks before calling `retrieve_password()`
    // (`check_ajax_referer()` plus `current_user_can( 'edit_user' )` in
    // wp_ajax_send_password_reset(); the bulk-action nonce plus the users.php
    // screen capability), and neither ever renders the widget.
    //
    // Gated on the capability, NOT on `is_admin()` alone: admin-ajax.php sets
    // WP_ADMIN for unauthenticated callers too, so an `is_admin()`-only branch
    // would be claimable by any anonymous POST — the same value-independent
    // context criterion rejected as BK-1/IN-8 in Modul 27. `is_admin()` is
    // still required on top of the capability so that a logged-in
    // administrator using the public (or WooCommerce) lost-password form keeps
    // having to solve the challenge like everybody else.
    if ( is_admin() && current_user_can( 'edit_users' ) ) {
        return 'admin';
    }

    // A genuine REST request never carries our widget either. Only the
    // REST_REQUEST constant is consulted — never `$_GET['rest_route']` in any
    // form: WordPress core sets the constant itself in `rest_api_loaded()`,
    // whereas the query parameter is attacker-supplied and completely inert at
    // entry points that never call `parse_request()`. Treating its mere
    // presence as "this is REST" is BK-1/IN-8; see the long note in
    // includes/forms/login.php.
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        return 'rest';
    }

    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        return 'xmlrpc';
    }

    if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
        return 'cron';
    }

    // Consistent with the non-interactive guard every other module already
    // carries (login, interceptor, firewall, rate limiter).
    if ( 'cli' === php_sapi_name() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
        return 'cli';
    }

    return null;
}

/**
 * Human-readable label for an exemption reason, for the event log.
 *
 * @param string $reason Reason key from creationell_captcha_password_reset_exempt_reason().
 */
function creationell_captcha_password_reset_exempt_label( string $reason ): string {
    switch ( $reason ) {
        case 'admin':
            return __( 'Administrativer Passwort-Reset', 'creationell-captcha' );
        case 'rest':
            return __( 'REST-Request', 'creationell-captcha' );
        case 'xmlrpc':
            return __( 'XML-RPC-Request', 'creationell-captcha' );
        case 'cron':
            return __( 'Cron-Lauf', 'creationell-captcha' );
        case 'cli':
            return __( 'Kommandozeile (WP-CLI)', 'creationell-captcha' );
    }

    return $reason;
}

/**
 * Verifies the captcha during a password-reset request.
 *
 * @param WP_Error $errors Password-reset errors (passed by WordPress >= 5.4).
 */
function creationell_captcha_password_reset_verify( $errors ): void {
    if ( ! creationell_captcha_password_reset_enabled() ) {
        return;
    }

    $exempt = creationell_captcha_password_reset_exempt_reason();
    if ( null !== $exempt ) {
        /** This action is documented in includes/rest.php. */
        do_action(
            'creationell_captcha_event',
            'verified',
            [
                'plugin' => 'WordPress',
                'action' => 'password_reset',
                'reason' => creationell_captcha_password_reset_exempt_label( $exempt ),
            ]
        );
        return;
    }

    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        do_action(
            'creationell_captcha_event',
            'verified',
            [
                'plugin' => 'WordPress',
                'action' => 'password_reset',
                'reason' => $bypass['reason'],
            ]
        );
        return;
    }

    $verified = creationell_captcha_verify_request();
    $context  = [
        'plugin' => 'WordPress',
        'action' => 'password_reset',
    ];
    if ( ! $verified ) {
        $context['reason'] = __( 'Challenge ungültig oder fehlend', 'creationell-captcha' );
    }
    /** This action is documented in includes/rest.php. */
    do_action( 'creationell_captcha_event', $verified ? 'verified' : 'failed', $context );

    if ( ! $verified && $errors instanceof WP_Error ) {
        $errors->add(
            'creationell_captcha_failed',
            __( '<strong>Fehler:</strong> Die Sicherheitsabfrage wurde nicht bestanden.', 'creationell-captcha' )
        );
    }
}
add_action( 'lostpassword_post', 'creationell_captcha_password_reset_verify' );
