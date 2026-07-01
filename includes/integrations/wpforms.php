<?php
/**
 * WPForms integration.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether the WPForms integration is active.
 */
function creationell_captcha_wpforms_active(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }
    if ( ! class_exists( 'WPForms' ) ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_wpforms'] );
}

/**
 * Auto-injects the widget directly before the WPForms submit button.
 *
 * Fires inside the <form> element, so the hidden `altcha` input that the
 * widget emits is part of the WPForms submission.
 *
 * @param array<string, mixed> $form_data WPForms form configuration.
 * @param mixed                $form      WPForms form post (unused, optional — der
 *                                        Hook `wpforms_display_submit_before` liefert nur $form_data).
 */
function creationell_captcha_wpforms_inject( array $form_data, $form = null ): void {
    unset( $form );

    if ( ! creationell_captcha_wpforms_active() ) {
        return;
    }

    $form_id = isset( $form_data['id'] ) ? (int) $form_data['id'] : 0;

    /**
     * Filters whether the widget is auto-injected into a WPForms form.
     *
     * Return false to skip auto-injection for a specific form.
     *
     * @param bool $inject  Whether to inject. Default true.
     * @param int  $form_id The WPForms form ID.
     */
    if ( ! apply_filters( 'creationell_captcha_wpforms_autoinject', true, $form_id ) ) {
        return;
    }

    creationell_captcha_render_widget();
}
add_action( 'wpforms_display_submit_before', 'creationell_captcha_wpforms_inject', 10, 1 );

/**
 * Verifies the captcha on a WPForms submission.
 *
 * Hooked on `wpforms_process` (action). On failure we set an entry in
 * `wpforms()->process->errors[ $form_id ]['header']` — WPForms then renders
 * the message above the form and refuses to save the entry.
 *
 * @param array<int, mixed>    $fields    Sanitized field values (unused).
 * @param array<string, mixed> $entry     Raw `$_POST['wpforms']` (unused).
 * @param array<string, mixed> $form_data Form configuration.
 */
function creationell_captcha_wpforms_verify( $fields, $entry, $form_data ): void {
    unset( $fields, $entry );

    if ( ! creationell_captcha_wpforms_active() ) {
        return;
    }

    $form_id = isset( $form_data['id'] ) ? (int) $form_data['id'] : 0;
    $context = [
        'plugin'  => 'WPForms',
        'action'  => 'wpforms',
        'form_id' => (string) $form_id,
    ];

    /** This action is documented in includes/rest.php. */
    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        $context['reason'] = $bypass['reason'];
        do_action( 'creationell_captcha_event', 'verified', $context );
        return;
    }

    if ( creationell_captcha_verify_request() ) {
        do_action( 'creationell_captcha_event', 'verified', $context );
        return;
    }

    $context['reason'] = __( 'Challenge ungültig oder fehlend', 'creationell-captcha' );
    do_action( 'creationell_captcha_event', 'failed', $context );
    creationell_captcha_log( 'WPForms submission rejected — captcha verification failed.' );

    if ( function_exists( 'wpforms' ) && $form_id > 0 ) {
        $process = wpforms()->process;
        if ( is_object( $process ) && isset( $process->errors ) && is_array( $process->errors ) ) {
            $process->errors[ $form_id ]['header'] =
                __( 'Die Sicherheitsabfrage wurde nicht bestanden.', 'creationell-captcha' );
        }
    }
}
add_action( 'wpforms_process', 'creationell_captcha_wpforms_verify', 10, 3 );
