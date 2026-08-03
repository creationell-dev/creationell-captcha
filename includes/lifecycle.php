<?php
/**
 * Activation and deactivation routines.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Runs on plugin activation: seeds default options and HMAC secrets.
 */
function creationell_captcha_activate(): void {
    if ( false === get_option( 'creationell_captcha_settings', false ) ) {
        add_option( 'creationell_captcha_settings', creationell_captcha_get_default_settings() );
    }

    $secrets = get_option( 'creationell_captcha_secrets', false );
    if ( ! is_array( $secrets ) || empty( $secrets['signature'] ) || empty( $secrets['key_signature'] ) ) {
        creationell_captcha_generate_secrets();
    }

    // DS-1: put the retention sweep on the schedule right away instead of
    // waiting for the first front-end `init`.
    \Creationell\Captcha\Analytics::ensure_prune_schedule();

    update_option( 'creationell_captcha_version', CREATIONELL_CAPTCHA_VERSION );
}

/**
 * Runs on plugin deactivation: clears every cron slot the plugin owns, sweeps
 * the expired replay markers out of the options table and lets every module
 * react via the `creationell_captcha_deactivated` action hook.
 *
 * B-M5: cron slots and replay markers are per-site data, so on a network-wide
 * deactivation the work has to be done on every site of the network — not just
 * on whichever site happens to be current when `deactivate_{$plugin}` fires
 * (that is the network admin's site, usually the main site). `uninstall.php`
 * already walks the network this way since DS-3; this is the same walk for the
 * same reason.
 *
 * @param bool $network_deactivating Whether the plugin is being deactivated for
 *                                   the whole network. WordPress passes this as
 *                                   the single argument of `deactivate_{$plugin}`
 *                                   (wp-admin/includes/plugin.php,
 *                                   `deactivate_plugins()`); the default keeps
 *                                   the function callable by hand.
 */
function creationell_captcha_deactivate( bool $network_deactivating = false ): void {
    if ( $network_deactivating && is_multisite() ) {
        creationell_captcha_deactivate_network();
    } else {
        // Single-site case — including a plugin that is activated per site
        // inside a network. Only that one site's activation is ending, so only
        // that site's cron slots and markers are touched.
        creationell_captcha_deactivate_site();
    }

    /**
     * Fires once on plugin deactivation, after the plugin's own scheduled
     * cron slots have been cleared and its expired replay markers removed.
     * Modules that registered their own cron jobs or transients should clean
     * them up here.
     *
     * Fires exactly once even when the deactivation was network-wide and the
     * walk above visited many sites — the current site is the one that was
     * current when the hook fired. A handler that owns per-site data has to
     * walk the network itself; `$network_deactivating` says when that is
     * necessary.
     *
     * @since 0.15.0
     *
     * @param bool $network_deactivating Whether the plugin was deactivated for the whole network.
     */
    do_action( 'creationell_captcha_deactivated', $network_deactivating );
}

/**
 * The deactivation work for exactly one site: clears the three cron slots this
 * plugin owns there and sweeps that site's expired replay markers.
 *
 * Everything in here is relative to the CURRENT site, so it is safe to call
 * from inside a `switch_to_blog()` bracket — `wp_clear_scheduled_hook()` works
 * on the current site's `cron` option and the sweep re-reads `$wpdb->options`
 * on every call.
 */
function creationell_captcha_deactivate_site(): void {
    wp_clear_scheduled_hook( 'creationell_captcha_refresh_cloudflare_ips' );

    // FU-4: Welle 1 moved the replay guard from transients to plain options so
    // the claim could be a single atomic INSERT IGNORE (CM-9). Plain options
    // have no expiry of their own; while the plugin is loaded the only thing
    // that removes them is `Engine::cleanup_replay_markers()`, run from the
    // cron hook cleared here (or inline from verify() when that slot is badly
    // overdue). Deactivating the plugin unloads the handler, so leaving the
    // slot behind means a cron entry firing into nothing while the marker rows
    // sit in wp_options. The two paths that reach the rows without the plugin
    // being loaded are the sweep below and `uninstall.php`.
    wp_clear_scheduled_hook( \Creationell\Captcha\Engine::CLEANUP_HOOK );

    // DS-1: same for the retention sweep added in this release.
    wp_clear_scheduled_hook( \Creationell\Captcha\Analytics::PRUNE_HOOK );

    creationell_captcha_delete_expired_replay_markers();
}

/**
 * Runs the per-site deactivation work on every site of the network.
 *
 * Walks the sites in batches instead of materialising every site id at once —
 * same shape and same batch size as the DS-3 walk in `uninstall.php`, so both
 * routines behave the same way on the same network.
 *
 * @return int Number of sites processed.
 */
function creationell_captcha_deactivate_network(): int {
    $batch     = 100;
    $offset    = 0;
    $processed = 0;

    do {
        $site_ids = get_sites(
            [
                'fields'  => 'ids',
                'number'  => $batch,
                'offset'  => $offset,
                'orderby' => 'id',
            ]
        );

        foreach ( $site_ids as $site_id ) {
            switch_to_blog( (int) $site_id );
            creationell_captcha_deactivate_site();
            restore_current_blog();
            ++$processed;
        }

        $offset += $batch;
    } while ( count( $site_ids ) === $batch );

    return $processed;
}

/**
 * Deletes those replay-marker options of the current site whose lifetime has
 * already run out.
 *
 * Live markers are deliberately left in place. Removing them as well would be
 * tidier — nothing sweeps them while the plugin is unloaded — but it would
 * re-open the window CM-9 closed: a payload whose marker is gone passes
 * `Engine::verify()` a second time as long as its own signed `expiresAt` has
 * not been reached (`challenge_expiry`, default 300 s, settings range
 * 60–3600 s, checked inside the ALTCHA library independently of the marker —
 * lib/altcha-org/altcha/src/Altcha.php, `verifySolution()`). Deactivating
 * and re-activating inside that window is an everyday admin action — update,
 * debugging, changing the plugin load order — so the marker has to survive it.
 *
 * What stays behind when the plugin is never re-activated is one option row per
 * payload whose challenge has not run out yet (since 1.1.0 the marker lifetime
 * is the challenge's own remaining validity — `Engine::replay_marker_lifetime()`).
 * `uninstall.php` removes those unconditionally, and after a re-activation the
 * next successful claim re-arms the cron slot cleared in
 * `creationell_captcha_deactivate_site()` (`Engine::claim_replay_marker()` →
 * `schedule_replay_cleanup()`), whose sweep then drops them.
 *
 * The predicate is the one `Engine::cleanup_replay_markers()` uses: the marker
 * value is the Unix timestamp the marker expires at, written by
 * `Engine::claim_replay_marker()`. A row with a non-numeric value casts to 0
 * and is therefore treated as expired — same fail-open-on-garbage behaviour as
 * the sweep, and no caller outside the engine ever writes these rows.
 *
 * @return int Number of option rows removed.
 */
function creationell_captcha_delete_expired_replay_markers(): int {
    global $wpdb;

    $like = $wpdb->esc_like( \Creationell\Captcha\Engine::REPLAY_PREFIX ) . '%';

    return (int) $wpdb->query(
        $wpdb->prepare(
            'DELETE FROM %i WHERE `option_name` LIKE %s AND CAST(`option_value` AS UNSIGNED) <= %d',
            $wpdb->options,
            $like,
            time()
        )
    );
}
