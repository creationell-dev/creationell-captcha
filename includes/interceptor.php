<?php
/**
 * Interceptor bootstrap: init-hook registration and the developer API.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Runs the request interceptor. Hooked on `init` at priority 1 so it fires
 * before any form-processing handler.
 */
function creationell_captcha_run_interceptor(): void {
    ( new \Creationell\Captcha\Interceptor() )->run();
}
add_action( 'init', 'creationell_captcha_run_interceptor', 1 );

/**
 * Registers one or more path patterns to be guarded by the interceptor.
 *
 * Developer API — later form-plugin integrations call this to protect their
 * submission endpoints without an admin entering patterns by hand. The
 * patterns are merged into the `creationell_captcha_interceptor_paths` filter.
 *
 * @param string|array<int, string> $patterns A path pattern or list of patterns.
 */
function creationell_captcha_protect_path( string|array $patterns ): void {
    $patterns = array_values( array_filter(
        array_map(
            static function ( $pattern ): string {
                return trim( (string) $pattern );
            },
            (array) $patterns
        ),
        static function ( string $pattern ): bool {
            return '' !== $pattern;
        }
    ) );

    if ( empty( $patterns ) ) {
        return;
    }

    add_filter(
        'creationell_captcha_interceptor_paths',
        static function ( array $list ) use ( $patterns ): array {
            return array_merge( $list, $patterns );
        }
    );
}
