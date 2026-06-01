<?php
/**
 * Uninstall routine for CreaCaptcha.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'creationell_captcha_settings' );
delete_option( 'creationell_captcha_version' );
delete_option( 'creationell_captcha_secrets' );
delete_option( 'creationell_captcha_analytics' );
delete_option( 'creationell_captcha_analytics_hourly' );
delete_option( 'creationell_captcha_cloudflare_ips' );

// Remove all plugin transients (replay-guard, code-challenge tokens,
// rate-limit buckets, plugin-updater cache+lock — anything with the
// creationell_captcha_ prefix).
global $wpdb;
$like         = $wpdb->esc_like( '_transient_creationell_captcha_' ) . '%';
$timeout_like = $wpdb->esc_like( '_transient_timeout_creationell_captcha_' ) . '%';
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
        $like,
        $timeout_like
    )
);

// Remove the optional analytics event-log table (table name mirrors
// Creationell\Captcha\Analytics::table_name() — uninstall runs without the
// plugin loaded, so the name is repeated here).
$creationell_captcha_events_table = $wpdb->prefix . 'creationell_captcha_events';
$wpdb->query( "DROP TABLE IF EXISTS `{$creationell_captcha_events_table}`" );
