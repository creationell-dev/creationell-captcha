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
 * Verifies the captcha during a password-reset request.
 *
 * @param WP_Error $errors Password-reset errors (passed by WordPress >= 5.4).
 */
function creationell_captcha_password_reset_verify( $errors ): void {
    if ( ! creationell_captcha_password_reset_enabled() ) {
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
