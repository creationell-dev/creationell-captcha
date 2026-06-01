<?php
/**
 * Contact Form 7 integration.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether the Contact Form 7 integration is active.
 */
function creationell_captcha_cf7_active(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }
    if ( ! class_exists( 'WPCF7_ContactForm' ) ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_cf7'] );
}

/**
 * Registers the [creationell_captcha] Contact Form 7 form-tag.
 *
 * Registered unconditionally (no creationell_captcha_cf7_active() guard) so CF7
 * always recognises the tag and never prints it as raw text; the tag handler
 * returns an empty string when the integration is inactive.
 */
function creationell_captcha_cf7_register_tag(): void {
    if ( function_exists( 'wpcf7_add_form_tag' ) ) {
        wpcf7_add_form_tag(
            'creationell_captcha',
            'creationell_captcha_cf7_tag_handler',
            [ 'display-block' => true ]
        );
    }
}
add_action( 'wpcf7_init', 'creationell_captcha_cf7_register_tag' );

/**
 * Renders the widget for the [creationell_captcha] form-tag.
 */
function creationell_captcha_cf7_tag_handler(): string {
    if ( ! creationell_captcha_cf7_active() ) {
        return '';
    }

    return creationell_captcha_get_widget_markup();
}

/**
 * Auto-injects the widget into CF7 forms without a [creationell_captcha] tag.
 *
 * @param string $elements The form's inner HTML.
 */
function creationell_captcha_cf7_auto_inject( string $elements ): string {
    if ( ! creationell_captcha_cf7_active() ) {
        return $elements;
    }

    $form = wpcf7_get_current_contact_form();
    if ( $form instanceof WPCF7_ContactForm
        && ! empty( $form->scan_form_tags( [ 'type' => 'creationell_captcha' ] ) )
    ) {
        return $elements; // The form-tag has already placed the widget.
    }

    $markup = creationell_captcha_get_widget_markup();

    // Insert before the submit button; fall back to appending.
    if ( preg_match( '/<input\b[^>]*\bwpcf7-submit\b/i', $elements, $matches, PREG_OFFSET_CAPTURE ) ) {
        $offset = (int) $matches[0][1];

        return substr( $elements, 0, $offset ) . $markup . substr( $elements, $offset );
    }

    return $elements . $markup;
}
add_filter( 'wpcf7_form_elements', 'creationell_captcha_cf7_auto_inject' );

/**
 * Verifies the captcha on a Contact Form 7 submission.
 *
 * Hooked on `wpcf7_spam`: returning true marks the submission as spam, which
 * CF7 then rejects through its standard flow.
 *
 * @param mixed $spam       Whether CF7 already classified the submission as spam.
 * @param mixed $submission The WPCF7_Submission object.
 */
function creationell_captcha_cf7_verify( $spam, $submission ): bool {
    if ( $spam || ! creationell_captcha_cf7_active() ) {
        return (bool) $spam;
    }

    $payload = '';
    if ( is_object( $submission ) && method_exists( $submission, 'get_posted_data' ) ) {
        $value   = $submission->get_posted_data( 'altcha' );
        $payload = is_string( $value ) ? $value : '';
    }

    $form    = wpcf7_get_current_contact_form();
    $context = [
        'plugin'  => 'Contact Form 7',
        'action'  => 'cf7',
        'form_id' => ( $form instanceof WPCF7_ContactForm ) ? (string) $form->id() : '',
    ];

    /** This action is documented in includes/rest.php. */
    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        $context['reason'] = $bypass['reason'];
        do_action( 'creationell_captcha_event', 'verified', $context );
        return false;
    }

    if ( creationell_captcha_verify_payload( $payload ) ) {
        do_action( 'creationell_captcha_event', 'verified', $context );

        return false;
    }

    $context['reason'] = __( 'Challenge ungültig oder fehlend', 'creationell-captcha' );
    do_action( 'creationell_captcha_event', 'failed', $context );
    creationell_captcha_log( 'CF7 submission rejected — captcha verification failed.' );

    return true;
}
add_filter( 'wpcf7_spam', 'creationell_captcha_cf7_verify', 10, 2 );
