<?php
/**
 * WP-CLI: simulates the bypass evaluation with caller-supplied inputs.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha\CLI;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

use WP_CLI;

/**
 * `wp creacaptcha test-bypass`
 */
class Test_Bypass_Command {

    /**
     * Simulates the bypass evaluation with the supplied flag values. Flags are
     * optional — anything not provided is treated as non-matching.
     *
     * Exit code: 0 if the request would be bypassed, 1 otherwise.
     *
     * ## OPTIONS
     *
     * [--ip=<ip>]
     * : IP address (IPv4 or IPv6) to test against the IP allowlist.
     *
     * [--ua=<user-agent>]
     * : User-Agent string to test against the UA bypass patterns.
     *
     * [--cookie=<name_value>]
     * : Cookie pair to test against the cookie bypass list (format: name=value).
     *   The flag may be repeated. Each value must contain exactly one `=` — the
     *   part before the first `=` is the cookie name.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha test-bypass --ip=203.0.113.4
     *     wp creacaptcha test-bypass --ua="Mozilla/5.0"
     *     wp creacaptcha test-bypass --cookie="my_pass=abc"
     *     wp creacaptcha test-bypass --ip=203.0.113.4 --ua="GoogleBot" --cookie="my_pass=abc"
     *
     * @when after_wp_load
     *
     * @param array<int, string>                    $args       Positional arguments.
     * @param array<string, string|array<int,string>> $assoc_args Associative arguments.
     */
    public function __invoke( array $args, array $assoc_args ): void {
        $ip = isset( $assoc_args['ip'] ) ? (string) $assoc_args['ip'] : null;
        $ua = isset( $assoc_args['ua'] ) ? (string) $assoc_args['ua'] : null;

        $cookies     = [];
        $cookie_args = $assoc_args['cookie'] ?? [];
        if ( ! is_array( $cookie_args ) ) {
            $cookie_args = [ (string) $cookie_args ];
        }
        foreach ( $cookie_args as $raw ) {
            $raw = (string) $raw;
            $pos = strpos( $raw, '=' );
            if ( false === $pos ) {
                WP_CLI::warning( sprintf( 'Cookie-Wert „%s" ignoriert (erwartet: name=value).', $raw ) );
                continue;
            }
            $name              = substr( $raw, 0, $pos );
            $value             = substr( $raw, $pos + 1 );
            $cookies[ $name ]  = $value;
        }

        $result = creationell_captcha_evaluate_bypass( $ip, $ua, $cookies );

        if ( false === $result ) {
            WP_CLI::log( 'Kein Bypass — keine Regel hat getroffen.' );
            WP_CLI::halt( 1 );
        }

        WP_CLI::success(
            sprintf(
                'Würde bypasst werden — Quelle: %s (matched: %s).',
                $result['reason'],
                $result['source']
            )
        );
    }
}
