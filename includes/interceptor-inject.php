<?php
/**
 * Auto-injects the ALTCHA widget into every <form> on pages matching the
 * configured inject paths.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Conditionally starts the output buffer on template_redirect priority 0.
 * The buffer only runs when (a) the master interceptor toggle is on, (b) at
 * least one inject path is configured, AND (c) the current request path
 * matches that pattern list. On non-matching pages the request is unaffected.
 */
function creationell_captcha_interceptor_inject_buffer_start(): void {
    if ( creationell_captcha_is_disabled() || is_admin() ) {
        return;
    }
    if ( wp_doing_ajax() || wp_doing_cron() ) {
        return;
    }
    if ( defined( 'WP_CLI' ) && WP_CLI ) {
        return;
    }
    if ( is_feed() ) {
        return;
    }

    $settings = creationell_captcha_get_settings();
    if ( empty( $settings['interceptor_enabled'] ) ) {
        return;
    }

    $patterns = (array) ( $settings['interceptor_inject_paths'] ?? [] );
    if ( empty( $patterns ) ) {
        return;
    }

    $uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
    $path = (string) wp_parse_url( $uri, PHP_URL_PATH );

    if ( ! \Creationell\Captcha\Interceptor::match_path( $path, $patterns ) ) {
        return;
    }

    // Enqueue the altcha widget script BEFORE the buffer starts so it gets
    // emitted by wp_print_footer_scripts. The buffer callback fires after the
    // footer has been printed — enqueuing inside the callback would be a no-op.
    wp_enqueue_script( 'creationell-captcha-altcha' );

    ob_start( 'creationell_captcha_interceptor_inject_buffer' );
}
add_action( 'template_redirect', 'creationell_captcha_interceptor_inject_buffer_start', 0 );

/**
 * Buffer callback. Replaces every `<form …>…</form>` with the same form plus
 * an `<altcha-widget>` inserted directly before `</form>`. Idempotent — forms
 * that already contain `<altcha-widget` are returned unchanged.
 *
 * @param string $html Full page HTML.
 */
function creationell_captcha_interceptor_inject_buffer( string $html ): string {
    if ( '' === $html || false === strpos( $html, '</form>' ) ) {
        return $html;
    }

    $widget = creationell_captcha_get_widget_markup();
    if ( '' === $widget ) {
        return $html;
    }

    $result = preg_replace_callback(
        '#<form\b[^>]*>(.*?)</form>#is',
        static function ( array $matches ) use ( $widget ): string {
            // Idempotent — skip forms that already carry the widget.
            if ( false !== stripos( $matches[0], '<altcha-widget' ) ) {
                return $matches[0];
            }
            // Insert directly before the closing </form>.
            $end_pos = strrpos( $matches[0], '</form>' );
            if ( false === $end_pos ) {
                return $matches[0];
            }
            return substr_replace( $matches[0], $widget, $end_pos, 0 );
        },
        $html
    );

    return is_string( $result ) ? $result : $html;
}
