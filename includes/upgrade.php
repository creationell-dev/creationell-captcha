<?php
/**
 * Version-gated upgrade routine.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Runs schema migrations when the stored version differs from the running one.
 *
 * Hooked on admin_init. When the event-log table already exists it is re-run
 * through dbDelta so new columns are added; a missing table is left alone — it
 * is created on demand when the event log is switched on.
 */
function creationell_captcha_maybe_upgrade(): void {
    $stored = (string) get_option( 'creationell_captcha_version', '' );
    if ( $stored === CREATIONELL_CAPTCHA_VERSION ) {
        return;
    }

    $analytics = creationell_captcha_analytics();
    if ( $analytics->table_exists() ) {
        $analytics->ensure_table();
    }

    creationell_captcha_migrate_widget_mode();

    update_option( 'creationell_captcha_version', CREATIONELL_CAPTCHA_VERSION );
}
add_action( 'admin_init', 'creationell_captcha_maybe_upgrade' );

/**
 * Migrates the legacy `widget_mode` setting (Modul 11a) to the new
 * `widget_display` + `widget_auto_trigger` pair (Modul 14). Idempotent — if
 * `widget_display` is already present in the stored option, the migration is
 * skipped.
 *
 * Mapping:
 *   visible → widget_display=standard,  widget_auto_trigger=none
 *   auto    → widget_display=invisible, widget_auto_trigger=onload
 *   overlay → widget_display=floating,  widget_auto_trigger=onsubmit
 *
 * The legacy `widget_mode` key is removed from the option once the new keys
 * are in place.
 */
function creationell_captcha_migrate_widget_mode(): void {
    $stored = get_option( 'creationell_captcha_settings', [] );
    if ( ! is_array( $stored ) ) {
        return;
    }

    // Idempotency guard: if the user has already saved settings under v0.20.0,
    // widget_display will be present and we have nothing to migrate.
    if ( array_key_exists( 'widget_display', $stored ) ) {
        if ( array_key_exists( 'widget_mode', $stored ) ) {
            unset( $stored['widget_mode'] );
            update_option( 'creationell_captcha_settings', $stored );
        }
        return;
    }

    $mode = isset( $stored['widget_mode'] ) ? (string) $stored['widget_mode'] : 'visible';

    $map = [
        'visible' => [ 'display' => 'standard',  'trigger' => 'none' ],
        'auto'    => [ 'display' => 'invisible', 'trigger' => 'onload' ],
        'overlay' => [ 'display' => 'floating',  'trigger' => 'onsubmit' ],
    ];

    $target = $map[ $mode ] ?? $map['visible'];

    $stored['widget_display']      = $target['display'];
    $stored['widget_auto_trigger'] = $target['trigger'];

    unset( $stored['widget_mode'] );

    update_option( 'creationell_captcha_settings', $stored );
}
