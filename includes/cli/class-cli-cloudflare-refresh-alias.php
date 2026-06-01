<?php
/**
 * WP-CLI: Deprecation alias for `wp creacaptcha refresh-cloudflare-ips`.
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
 * Single-method alias for the legacy `refresh-cloudflare-ips` top-level
 * command. Emits a deprecation warning and forwards to
 * `Cloudflare_Command::refresh()`.
 */
class Cloudflare_Refresh_Alias {

    /**
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function __invoke( array $args, array $assoc_args ): void {
        WP_CLI::warning( '`wp creacaptcha refresh-cloudflare-ips` ist veraltet — bitte `wp creacaptcha cloudflare refresh` verwenden.' );
        ( new Cloudflare_Command() )->refresh( $args, $assoc_args );
    }
}
