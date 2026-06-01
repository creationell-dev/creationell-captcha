<?php
/**
 * ALTCHA protection for the WordPress registration form.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether registration protection is enabled.
 */
function creationell_captcha_registration_enabled(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_registration'] );
}

/**
 * Renders the widget inside the registration form.
 */
function creationell_captcha_registration_render(): void {
    if ( creationell_captcha_registration_enabled() ) {
        creationell_captcha_render_widget();
    }
}
add_action( 'register_form', 'creationell_captcha_registration_render' );

/**
 * Verifies the captcha during registration.
 *
 * @param WP_Error $errors               Registration errors.
 * @param string   $sanitized_user_login Submitted user login.
 * @param string   $user_email           Submitted user email.
 * @return WP_Error
 */
function creationell_captcha_registration_verify( $errors, $sanitized_user_login, $user_email ) {
    unset( $sanitized_user_login, $user_email );

    if ( ! creationell_captcha_registration_enabled() ) {
        return $errors;
    }

    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        do_action(
            'creationell_captcha_event',
            'verified',
            [
                'plugin' => 'WordPress',
                'action' => 'registration',
                'reason' => $bypass['reason'],
            ]
        );
        return $errors;
    }

    $verified = creationell_captcha_verify_request();
    $context  = [
        'plugin' => 'WordPress',
        'action' => 'registration',
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

    return $errors;
}
add_filter( 'registration_errors', 'creationell_captcha_registration_verify', 10, 3 );
