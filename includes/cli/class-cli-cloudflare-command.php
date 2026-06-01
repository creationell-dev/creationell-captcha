<?php
/**
 * WP-CLI: Cloudflare-range cache operations.
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
 * `wp creacaptcha cloudflare …` — refresh, clear and status for the cached
 * Cloudflare IP-range list.
 */
class Cloudflare_Command {

    /**
     * Manually refreshes the cached Cloudflare-range list.
     *
     * Fetches `https://www.cloudflare.com/ips-v4` and `ips-v6`, validates each
     * line as a CIDR range, and writes the result to the option
     * `creationell_captcha_cloudflare_ips` (with source=remote and a fresh
     * timestamp). Fails gracefully if either endpoint returns fewer than five
     * valid entries — the bundled snapshot remains in effect.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha cloudflare refresh
     *
     * @when after_wp_load
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function refresh( $args, $assoc_args ): void {
        $result = creationell_captcha_refresh_cloudflare_ips_now();

        if ( ! $result['ok'] ) {
            WP_CLI::error( $result['error'] ?? 'unknown error' );
        }

        $fetched_at = (int) ( $result['fetched_at'] ?? 0 );

        WP_CLI::success(
            sprintf(
                'Cloudflare ranges refreshed: %d IPv4, %d IPv6. fetched_at=%s',
                $result['v4'],
                $result['v6'],
                $fetched_at > 0 ? gmdate( 'Y-m-d H:i:s', $fetched_at ) . ' UTC' : 'n/a'
            )
        );
    }

    /**
     * Deletes the cached Cloudflare-range option. The next read falls back to
     * the bundled snapshot until a refresh runs.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha cloudflare clear --yes
     *
     * @when after_wp_load
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function clear( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Den Cloudflare-IP-Cache wirklich leeren?', $assoc_args );

        if ( creationell_captcha_clear_cloudflare_cache() ) {
            WP_CLI::success( 'Cloudflare-IP-Cache geleert. Nächster Zugriff nutzt die gebündelten Ranges.' );
            return;
        }

        WP_CLI::log( 'Kein Cache vorhanden — nichts zu leeren.' );
    }

    /**
     * Shows the current Cloudflare-cache state.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha cloudflare status
     *
     * @when after_wp_load
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function status( $args, $assoc_args ): void {
        $format = $assoc_args['format'] ?? 'table';
        $cached = get_option( 'creationell_captcha_cloudflare_ips', [] );

        $rows = [];

        if ( ! is_array( $cached ) || empty( $cached ) ) {
            $rows[] = [ 'feld' => 'Quelle', 'wert' => 'leer (Cache nicht vorhanden — Fallback auf Bundled-Snapshot)' ];
            $rows[] = [ 'feld' => 'IPv4-Ranges', 'wert' => '—' ];
            $rows[] = [ 'feld' => 'IPv6-Ranges', 'wert' => '—' ];
            $rows[] = [ 'feld' => 'Letzter Refresh', 'wert' => '—' ];
        } else {
            $v4         = is_array( $cached['v4'] ?? null ) ? count( $cached['v4'] ) : 0;
            $v6         = is_array( $cached['v6'] ?? null ) ? count( $cached['v6'] ) : 0;
            $fetched_at = (int) ( $cached['fetched_at'] ?? 0 );
            $source     = (string) ( $cached['source'] ?? '—' );

            $age_label = '—';
            if ( $fetched_at > 0 ) {
                $age_label = sprintf(
                    '%s UTC (vor %s)',
                    gmdate( 'Y-m-d H:i:s', $fetched_at ),
                    human_time_diff( $fetched_at, time() )
                );
            }

            $rows[] = [ 'feld' => 'Quelle', 'wert' => $source ];
            $rows[] = [ 'feld' => 'IPv4-Ranges', 'wert' => (string) $v4 ];
            $rows[] = [ 'feld' => 'IPv6-Ranges', 'wert' => (string) $v6 ];
            $rows[] = [ 'feld' => 'Letzter Refresh', 'wert' => $age_label ];
        }

        $next = wp_next_scheduled( 'creationell_captcha_refresh_cloudflare_ips' );
        if ( false === $next ) {
            $rows[] = [ 'feld' => 'Nächster Cron-Run', 'wert' => 'kein Cron geplant' ];
        } else {
            $rows[] = [
                'feld' => 'Nächster Cron-Run',
                'wert' => sprintf(
                    '%s UTC (in %s)',
                    gmdate( 'Y-m-d H:i:s', (int) $next ),
                    human_time_diff( time(), (int) $next )
                ),
            ];
        }

        \WP_CLI\Utils\format_items( $format, $rows, [ 'feld', 'wert' ] );
    }
}
