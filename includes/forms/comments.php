<?php
/**
 * ALTCHA protection for the WordPress comment form.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether comment protection applies to the current request.
 */
function creationell_captcha_comments_active(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }

    $settings = creationell_captcha_get_settings();
    if ( empty( $settings['protect_comments'] ) ) {
        return false;
    }
    if ( ! empty( $settings['skip_logged_in'] ) && is_user_logged_in() ) {
        return false;
    }

    return true;
}

/**
 * Injects the widget just above the comment form submit button.
 *
 * @param string $submit_field The submit button field HTML.
 */
function creationell_captcha_comments_render( string $submit_field ): string {
    if ( ! creationell_captcha_comments_active() ) {
        return $submit_field;
    }

    ob_start();
    creationell_captcha_render_widget();

    return ob_get_clean() . $submit_field;
}
add_filter( 'comment_form_submit_field', 'creationell_captcha_comments_render' );

/**
 * Verifies the captcha before a comment is accepted.
 *
 * @param array<string, mixed> $commentdata Comment data.
 * @return array<string, mixed>
 */
function creationell_captcha_comments_verify( array $commentdata ): array {
    if ( ! creationell_captcha_comments_active() ) {
        return $commentdata;
    }

    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        do_action(
            'creationell_captcha_event',
            'verified',
            [
                'plugin' => 'WordPress',
                'action' => 'comment',
                'reason' => $bypass['reason'],
            ]
        );
        return $commentdata;
    }

    if ( ! creationell_captcha_verify_request() ) {
        do_action(
            'creationell_captcha_event',
            'failed',
            [
                'plugin' => 'WordPress',
                'action' => 'comment',
                'reason' => __( 'Challenge ungültig oder fehlend', 'creationell-captcha' ),
            ]
        );
        wp_die(
            esc_html__( 'Die Sicherheitsabfrage wurde nicht bestanden. Bitte gehen Sie zurück und versuchen Sie es erneut.', 'creationell-captcha' ),
            esc_html__( 'Sicherheitsabfrage fehlgeschlagen', 'creationell-captcha' ),
            [
                'response'  => 403,
                'back_link' => true,
            ]
        );
    }

    do_action(
        'creationell_captcha_event',
        'verified',
        [
            'plugin' => 'WordPress',
            'action' => 'comment',
        ]
    );

    return $commentdata;
}
add_filter( 'preprocess_comment', 'creationell_captcha_comments_verify' );
