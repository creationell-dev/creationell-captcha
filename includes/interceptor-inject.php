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

    // C1: same request-path root as the guard — the inject list and the guard
    // list must not disagree about `//kontakt` either (that decoupling is what
    // BK-16/CM-11 set out to close).
    $raw_path = creationell_captcha_request_path();

    // BK-5: match on the decoded path, exactly once and only after the query
    // has been split off — same contract as Interceptor::context(). Without it
    // the inject list and the guard list would disagree about /%6Bontakt: the
    // page would be served without a widget while the follow-up POST is
    // blocked (the decoupling BK-16/CM-11 describe).
    //
    // Both spellings are matched (Interceptor::match_request_path()) for the
    // same reason as the guard: an inject path that was configured
    // percent-encoded — the only spelling that worked up to 1.0.2 for a
    // non-ASCII slug — would otherwise stop rendering the widget on update,
    // leaving a form that looks unprotected. Symmetry with the guard list is
    // what keeps CM-11 from reappearing.
    $path = rawurldecode( $raw_path );

    if ( ! \Creationell\Captcha\Interceptor::match_request_path( $path, $raw_path, $patterns ) ) {
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

    if ( ! is_string( $result ) ) {
        /*
         * BK-16: preg_replace_callback() returns null on a PCRE runtime error
         * — most plausibly `pcre.backtrack_limit` on a large page. Falling back
         * to the untouched HTML is the right call and stays fail-closed (the
         * interceptor keeps rejecting the subsequent POST), but it used to be
         * completely silent: the admin saw a form without a widget whose
         * submission 403s and had nothing to go on. Log the PCRE reason so the
         * cause is findable. Deliberately a log line, not a behaviour change.
         */
        creationell_captcha_log(
            'interceptor inject: preg_replace_callback failed ('
            . preg_last_error_msg()
            . ') — page served without widget; POSTs to guarded paths keep failing closed. '
            . 'Check pcre.backtrack_limit / pcre.recursion_limit.'
        );

        return $html;
    }

    return $result;
}
