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

    // Only the interactive wp-login.php form posts a "wp-submit" field;
    // XML-RPC, REST, application passwords and programmatic auth do not.
    if ( ! isset( $_POST['wp-submit'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
        return $user;
    }
    if ( '' === (string) $username || '' === (string) $password ) {
        return $user;
    }
    if ( $user instanceof WP_Error ) {
        return $user; // WordPress already rejected this attempt.
    }

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
