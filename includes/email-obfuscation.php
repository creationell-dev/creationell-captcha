<?php
/**
 * Email-obfuscation bootstrap: content-filter mode and full-page-buffer mode.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers email obfuscation on `init`. The decoder script is always
 * registered; then, unless the kill-switch is set or the feature is off, the
 * configured mode is wired up — the content filters (module 7) or the
 * full-page output buffer (module 8).
 */
function creationell_captcha_register_email_obfuscation(): void {
    wp_register_script(
        'creationell-captcha-email',
        CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/email-obfuscation.js',
        [],
        CREATIONELL_CAPTCHA_VERSION,
        true
    );

    if ( creationell_captcha_is_disabled() ) {
        return;
    }

    $settings = creationell_captcha_get_settings();
    if ( empty( $settings['obfuscate_emails'] ) ) {
        return;
    }

    $obfuscator = new \Creationell\Captcha\EmailObfuscator();

    if ( 'buffer' === ( $settings['obfuscate_emails_mode'] ?? 'content' ) ) {
        creationell_captcha_register_email_buffer( $obfuscator );

        return;
    }

    // Content-filter mode (module 7): the late priority (20) ensures the final
    // HTML — after wpautop, make_clickable and third-party filters — is processed.
    $filters = [ 'the_content', 'the_excerpt', 'widget_text', 'widget_block_content', 'comment_text' ];
    foreach ( $filters as $filter ) {
        add_filter( $filter, [ $obfuscator, 'process' ], 20 );
    }
}
add_action( 'init', 'creationell_captcha_register_email_obfuscation' );

/**
 * Wires up the full-page-buffer mode: on `template_redirect` for non-feed
 * front-end requests it enqueues the decoder script and starts an output
 * buffer whose callback obfuscates the page body at flush time.
 *
 * @param \Creationell\Captcha\EmailObfuscator $obfuscator The obfuscator.
 */
function creationell_captcha_register_email_buffer( \Creationell\Captcha\EmailObfuscator $obfuscator ): void {
    add_action(
        'template_redirect',
        static function () use ( $obfuscator ): void {
            if ( is_feed() ) {
                return;
            }

            wp_enqueue_script( 'creationell-captcha-email' );

            ob_start(
                static function ( string $html ) use ( $obfuscator ): string {
                    if ( creationell_captcha_is_disabled() ) {
                        return $html;
                    }

                    return $obfuscator->process_page( $html );
                }
            );
        }
    );
}
