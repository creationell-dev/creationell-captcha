<?php
/**
 * Uninstall routine for CreaCaptcha.
 *
 * Runs without the plugin loaded, so every name it touches is repeated here
 * rather than taken from a constant — with the single exception of the
 * replay-marker prefix, whose class file is pulled in below.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// E4a: the replay-marker prefix is the one name this file does not repeat. A
// second copy of the literal is the kind that survives a rename and silently
// leaves every marker row behind, so it comes from its single source of truth
// instead. Loading the class file is safe here: WordPress is fully booted, the
// plugin directory is by definition still in place (this file lives in it), and
// class-engine.php only declares a class and registers a cron handler — nothing
// is instantiated and no vendor class is touched at include time. The guard
// covers the WP-CLI path, where the plugin was loaded at bootstrap and the
// class already exists.
if ( ! class_exists( \Creationell\Captcha\Engine::class, false ) ) {
    require_once __DIR__ . '/includes/class-engine.php';
}

/**
 * Removes every trace of the plugin from the site that is currently switched
 * to: options, replay markers, transients, cron slots and the event-log table.
 *
 * Reads `$wpdb` freshly on each call because `switch_to_blog()` repoints
 * `$wpdb->prefix` and `$wpdb->options` at the other site's tables.
 */
function creationell_captcha_uninstall_site(): void {
    global $wpdb;

    delete_option( 'creationell_captcha_settings' );
    delete_option( 'creationell_captcha_version' );
    delete_option( 'creationell_captcha_secrets' );
    delete_option( 'creationell_captcha_analytics' );
    delete_option( 'creationell_captcha_analytics_hourly' );
    delete_option( 'creationell_captcha_cloudflare_ips' );

    // DS-10 / FU-4: clearing the cron slots lived only in
    // creationell_captcha_deactivate(). WordPress does run deactivation before
    // uninstall on the normal path, but not when the plugin folder is deleted
    // over FTP or a database is restored from a backup taken while the plugin
    // was active — in those cases the slots survive as entries firing into a
    // handler that no longer exists. Clearing them here is idempotent.
    wp_clear_scheduled_hook( 'creationell_captcha_refresh_cloudflare_ips' );
    wp_clear_scheduled_hook( 'creationell_captcha_cleanup_replay_markers' );
    wp_clear_scheduled_hook( 'creationell_captcha_prune_events' );

    // Remove all plugin transients (code-challenge tokens, rate-limit buckets,
    // plugin-updater cache+lock — anything with the creationell_captcha_
    // prefix).
    $like         = $wpdb->esc_like( '_transient_creationell_captcha_' ) . '%';
    $timeout_like = $wpdb->esc_like( '_transient_timeout_creationell_captcha_' ) . '%';
    $wpdb->query(
        $wpdb->prepare(
            'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s',
            $wpdb->options,
            $like,
            $timeout_like
        )
    );

    // FU-4: the single-use replay markers are plain options, not transients
    // (Welle 1 needed an atomic INSERT IGNORE claim), so the transient sweep
    // above does not reach them and nothing expires them on its own.
    //
    // Unlike creationell_captcha_delete_expired_replay_markers(), which runs on
    // deactivation and spares live markers, this deletes every marker: after an
    // uninstall the plugin does not come back, so there is no Engine::verify()
    // left that a dropped marker could let a payload through.
    $replay_like = $wpdb->esc_like( \Creationell\Captcha\Engine::REPLAY_PREFIX ) . '%';
    $wpdb->query(
        $wpdb->prepare(
            'DELETE FROM %i WHERE option_name LIKE %s',
            $wpdb->options,
            $replay_like
        )
    );

    // Remove the optional analytics event-log table (table name mirrors
    // Creationell\Captcha\Analytics::table_name()).
    $wpdb->query(
        $wpdb->prepare(
            'DROP TABLE IF EXISTS %i',
            $wpdb->prefix . 'creationell_captcha_events'
        )
    );
}

/**
 * Removes the plugin's per-user data.
 *
 * B-M4: the hardening notice introduced in this release remembers per
 * administrator that it was dismissed. Without this, one `wp_usermeta` row per
 * administrator who ever clicked the notice away survives the uninstall — and
 * the routine above promises to remove "every trace".
 *
 * Deliberately NOT part of creationell_captcha_uninstall_site(): `wp_usermeta`
 * is a network-global table that `switch_to_blog()` does not repoint, so this
 * runs exactly once for the whole installation. `delete_metadata()` with
 * `$delete_all = true` ignores the object id and removes the key for every user
 * in a single statement.
 */
function creationell_captcha_uninstall_user_meta(): void {
    // Name mirrors CREATIONELL_CAPTCHA_HARDENING_DISMISS_META
    // (includes/hardening-migration.php); repeated because that file is not
    // loaded here.
    delete_metadata( 'user', 0, 'creationell_captcha_hardening_dismissed', '', true );
}

// DS-3: the routine used to run exactly once against $wpdb->prefix, i.e.
// against whichever site happened to be current. On a network-activated
// install every other site kept its options, its replay markers, its cron
// slots and its events table. Walk the network in batches so a large network
// does not have to materialise every site id at once.
if ( is_multisite() ) {
    $creationell_captcha_batch  = 100;
    $creationell_captcha_offset = 0;

    do {
        $creationell_captcha_site_ids = get_sites(
            [
                'fields'  => 'ids',
                'number'  => $creationell_captcha_batch,
                'offset'  => $creationell_captcha_offset,
                'orderby' => 'id',
            ]
        );

        foreach ( $creationell_captcha_site_ids as $creationell_captcha_site_id ) {
            switch_to_blog( (int) $creationell_captcha_site_id );
            creationell_captcha_uninstall_site();
            restore_current_blog();
        }

        $creationell_captcha_offset += $creationell_captcha_batch;
    } while ( count( $creationell_captcha_site_ids ) === $creationell_captcha_batch );
} else {
    creationell_captcha_uninstall_site();
}

creationell_captcha_uninstall_user_meta();
