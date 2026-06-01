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

    update_option( 'creationell_captcha_version', CREATIONELL_CAPTCHA_VERSION );
}

/**
 * Runs on plugin deactivation: clears scheduled cron slots and lets every
 * module react via the `creationell_captcha_deactivated` action hook.
 */
function creationell_captcha_deactivate(): void {
    wp_clear_scheduled_hook( 'creationell_captcha_refresh_cloudflare_ips' );

    /**
     * Fires once on plugin deactivation, after the plugin's own scheduled
     * cron slots have been cleared. Modules that registered their own cron
     * jobs or transients should clean them up here.
     *
     * @since 0.15.0
     */
    do_action( 'creationell_captcha_deactivated' );
}
