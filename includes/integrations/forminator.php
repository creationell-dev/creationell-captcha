<?php
/**
 * Forminator integration.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether the Forminator integration is active.
 */
function creationell_captcha_forminator_active(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }
    if ( ! class_exists( 'Forminator' ) ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_forminator'] );
}

/**
 * Auto-injects the widget before the submit button of a Forminator custom form.
 *
 * The `forminator_render_form_submit_markup` filter also fires for polls and
 * quizzes; injection is restricted to the `forminator_forms` post type.
 *
 * @param mixed $html    The submit-section HTML.
 * @param mixed $form_id The form's post ID.
 */
function creationell_captcha_forminator_inject( $html, $form_id ): string {
    $html = is_string( $html ) ? $html : '';

    if ( ! creationell_captcha_forminator_active() ) {
        return $html;
    }

    if ( 'forminator_forms' !== get_post_type( (int) $form_id ) ) {
        return $html; // Not a custom form (poll or quiz).
    }

    /**
     * Filters whether the widget is auto-injected into a Forminator form.
     *
     * Return false to skip auto-injection for a specific form.
     *
     * @param bool $inject  Whether to inject. Default true.
     * @param int  $form_id The Forminator form ID.
     */
    if ( ! apply_filters( 'creationell_captcha_forminator_autoinject', true, (int) $form_id ) ) {
        return $html;
    }

    return creationell_captcha_get_widget_markup() . $html;
}
add_filter( 'forminator_render_form_submit_markup', 'creationell_captcha_forminator_inject', 10, 2 );

/**
 * Verifies the captcha on a Forminator custom-form submission.
 *
 * Hooked on `forminator_custom_form_submit_errors` (custom forms only): a
 * non-empty errors array makes Forminator reject the submission.
 *
 * @param mixed $errors The current array of submission errors.
 * @return array<int, array<string, string>>
 */
function creationell_captcha_forminator_verify( $errors ): array {
    $errors = is_array( $errors ) ? $errors : [];

    if ( ! creationell_captcha_forminator_active() ) {
        return $errors;
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the payload is the token.
    $raw     = isset( $_POST['altcha'] ) ? wp_unslash( $_POST['altcha'] ) : '';
    $payload = is_string( $raw ) ? $raw : '';

    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- diagnostic form id only.
    $form_id = isset( $_POST['form_id'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['form_id'] ) ) : '';
    $context = [
        'plugin'  => 'Forminator',
        'action'  => 'forminator',
        'form_id' => $form_id,
    ];

    /** This action is documented in includes/rest.php. */
    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        $context['reason'] = $bypass['reason'];
        do_action( 'creationell_captcha_event', 'verified', $context );
        return $errors;
    }

    if ( creationell_captcha_verify_payload( $payload ) ) {
        do_action( 'creationell_captcha_event', 'verified', $context );

        return $errors;
    }

    $context['reason'] = __( 'Challenge ungültig oder fehlend', 'creationell-captcha' );
    do_action( 'creationell_captcha_event', 'failed', $context );
    creationell_captcha_log( 'Forminator submission rejected — captcha verification failed.' );
    // Forminator error shape: each element is [ field_name => error_string ].
    $errors[] = [
        'altcha' => __( 'Die Sicherheitsabfrage wurde nicht bestanden.', 'creationell-captcha' ),
    ];

    return $errors;
}
add_filter( 'forminator_custom_form_submit_errors', 'creationell_captcha_forminator_verify', 10, 1 );
