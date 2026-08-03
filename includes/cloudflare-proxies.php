<?php
/**
 * Cloudflare-Range-Loader and refresher.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Returns the bundled Cloudflare snapshot.
 *
 * @return array{v4: string[], v6: string[], updated_at: string}
 */
function creationell_captcha_cloudflare_snapshot(): array {
    /** @var array{v4: string[], v6: string[], updated_at: string} $data */
    $data = require __DIR__ . '/data/cloudflare-ips.php';
    return $data;
}

/**
 * The active CF range list: cached option (if fresh and valid) → bundled snapshot.
 *
 * The cached option is considered stale once it is older than 48 hours,
 * shielding against a silently broken cron job.
 *
 * Every entry is re-validated on read. The refresh path already filters what
 * it fetches, but the option is a persisted value: it can predate the day
 * `is_valid_ip_or_cidr()` started rejecting a prefix length of 0, and it can be
 * written from outside this file (`wp option update`, a restored backup). One
 * `0.0.0.0/0` in there turns every peer into a trusted proxy, which makes
 * `X-Forwarded-For` — and with it the client IP the whole bypass chain runs on
 * — spoofable (LK-13). The validator is the one in helpers.php, deliberately
 * not a second copy of the rule.
 *
 * A cached list that does not survive validation is not partially used: the
 * bundled snapshot is the safer answer than a list somebody has been editing.
 *
 * @return string[] IPv4 and IPv6 CIDR ranges, merged.
 */
function creationell_captcha_cloudflare_ranges(): array {
    $snapshot = creationell_captcha_cloudflare_snapshot();
    $bundled  = array_merge( $snapshot['v4'], $snapshot['v6'] );

    $cached = get_option( 'creationell_captcha_cloudflare_ips', [] );
    if ( ! is_array( $cached ) || empty( $cached['v4'] ) || empty( $cached['v6'] ) ) {
        return $bundled;
    }

    $fetched_at = isset( $cached['fetched_at'] ) ? (int) $cached['fetched_at'] : 0;
    if ( $fetched_at <= 0 || ( time() - $fetched_at ) > 48 * HOUR_IN_SECONDS ) {
        return $bundled;
    }

    $merged = array_merge( (array) $cached['v4'], (array) $cached['v6'] );
    $valid  = [];
    foreach ( $merged as $entry ) {
        /*
         * The guard above checks the CONTAINER, not the entries. A restored
         * backup or a `wp option patch` can leave a nested array in there — the
         * cast then warns on every request through the proxy chain — or a
         * serialised object without __toString, which raises an uncatchable
         * Error and turns the front end white as soon as `firewall_behind_proxy`
         * and the Cloudflare trust are on.
         *
         * Bailing out rather than skipping: an entry we cannot even read means
         * the option has been tampered with, and the bundled snapshot is the
         * safer answer than the remainder of a list somebody edited. The count
         * check below turns this into exactly that.
         */
        if ( ! is_scalar( $entry ) ) {
            creationell_captcha_log(
                'CF ranges: cached option holds a non-scalar entry (' . gettype( $entry )
                . ') — falling back to the bundled snapshot'
            );
            return $bundled;
        }
        $entry = trim( (string) $entry );
        if ( '' !== $entry && creationell_captcha_is_valid_ip_or_cidr( $entry ) ) {
            $valid[] = $entry;
        }
    }

    if ( count( $valid ) !== count( $merged ) ) {
        creationell_captcha_log(
            sprintf(
                'CF ranges: cached option rejected (%d of %d entries invalid) — falling back to the bundled snapshot',
                count( $merged ) - count( $valid ),
                count( $merged )
            )
        );
        return $bundled;
    }

    return $valid;
}

/**
 * Fetches the live Cloudflare ranges and writes them to the cache option.
 *
 * @return array{ok: bool, v4: int, v6: int, fetched_at: int|null, error: string|null}
 */
function creationell_captcha_refresh_cloudflare_ips_now(): array {
    $v4 = creationell_captcha_fetch_cloudflare_list( 'https://www.cloudflare.com/ips-v4' );
    $v6 = creationell_captcha_fetch_cloudflare_list( 'https://www.cloudflare.com/ips-v6' );

    // Sanity check: both endpoints must yield ≥ 5 valid CIDR entries.
    if ( count( $v4 ) < 5 || count( $v6 ) < 5 ) {
        $error = sprintf( 'CF refresh failed: v4=%d, v6=%d entries (need ≥ 5 each)', count( $v4 ), count( $v6 ) );
        creationell_captcha_log( $error );
        return [
            'ok'         => false,
            'v4'         => count( $v4 ),
            'v6'         => count( $v6 ),
            'fetched_at' => null,
            'error'      => $error,
        ];
    }

    $fetched_at = time();
    update_option(
        'creationell_captcha_cloudflare_ips',
        [
            'v4'         => $v4,
            'v6'         => $v6,
            'fetched_at' => $fetched_at,
            'source'     => 'remote',
        ],
        false
    );

    return [
        'ok'         => true,
        'v4'         => count( $v4 ),
        'v6'         => count( $v6 ),
        'fetched_at' => $fetched_at,
        'error'      => null,
    ];
}

/**
 * Deletes the cached Cloudflare-range option. The next read falls back to the
 * bundled snapshot. Returns true when the option existed and was deleted, false
 * when the option was absent or the delete failed.
 */
function creationell_captcha_clear_cloudflare_cache(): bool {
    return (bool) delete_option( 'creationell_captcha_cloudflare_ips' );
}
add_action( 'creationell_captcha_refresh_cloudflare_ips', 'creationell_captcha_refresh_cloudflare_ips_now' );

/**
 * Fetches one Cloudflare endpoint and returns the valid CIDR entries.
 *
 * @return string[]
 */
function creationell_captcha_fetch_cloudflare_list( string $url ): array {
    $response = wp_safe_remote_get( $url, [ 'timeout' => 10 ] );

    if ( is_wp_error( $response ) ) {
        creationell_captcha_log( 'CF fetch error: ' . $response->get_error_message() );
        return [];
    }
    $code = (int) wp_remote_retrieve_response_code( $response );
    if ( 200 !== $code ) {
        creationell_captcha_log( 'CF fetch non-200: ' . $code );
        return [];
    }

    $body  = (string) wp_remote_retrieve_body( $response );
    $lines = preg_split( '/\r\n|\r|\n/', $body ) ?: [];
    $valid = [];
    foreach ( $lines as $line ) {
        $line = trim( (string) $line );
        if ( '' !== $line && creationell_captcha_is_valid_ip_or_cidr( $line ) ) {
            $valid[] = $line;
        }
    }
    return $valid;
}

/**
 * Ensures the daily refresh cron slot is in sync with the auto-refresh toggle.
 *
 * Hooked on `update_option_creationell_captcha_settings` (fires on every
 * settings save). Deactivation cleanup is handled explicitly in
 * `creationell_captcha_deactivate()` to avoid re-scheduling the slot during
 * the deactivation handler.
 */
function creationell_captcha_sync_cloudflare_cron(): void {
    $settings = creationell_captcha_get_settings();
    $enabled  = ! empty( $settings['firewall_trust_cloudflare'] )
        && ! empty( $settings['firewall_cloudflare_auto_refresh'] );

    $next = wp_next_scheduled( 'creationell_captcha_refresh_cloudflare_ips' );

    if ( $enabled && false === $next ) {
        wp_schedule_event( time() + 60, 'daily', 'creationell_captcha_refresh_cloudflare_ips' );
    } elseif ( ! $enabled && false !== $next ) {
        wp_clear_scheduled_hook( 'creationell_captcha_refresh_cloudflare_ips' );
    }
}
add_action( 'update_option_creationell_captcha_settings', 'creationell_captcha_sync_cloudflare_cron' );
