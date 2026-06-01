<?php
/**
 * Admin asset loading.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Enqueues admin styles and scripts on the CreaCaptcha admin pages.
 *
 * @param string $hook_suffix Current admin page hook suffix.
 */
function creationell_captcha_enqueue_admin_assets( string $hook_suffix ): void {
    if ( ! in_array( $hook_suffix, creationell_captcha_tabbed_page_hooks(), true ) ) {
        return;
    }

    wp_enqueue_style(
        'creationell-captcha-admin',
        CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/css/admin.css',
        [],
        CREATIONELL_CAPTCHA_VERSION
    );

    wp_enqueue_script(
        'creationell-captcha-admin',
        CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/admin.js',
        [],
        CREATIONELL_CAPTCHA_VERSION,
        true
    );

    // WordPress-Color-Picker (Iris) für das widget_primary_color-Feld.
    // Lädt auf allen CreaCaptcha-Tab-Pages — der Overhead ist minimal und
    // erspart einen Per-Tab-Filter.
    wp_enqueue_style( 'wp-color-picker' );
    wp_enqueue_script( 'wp-color-picker' );
    wp_add_inline_script(
        'wp-color-picker',
        'jQuery(function($){$(".creationell-captcha-color").wpColorPicker();});'
    );
}
add_action( 'admin_enqueue_scripts', 'creationell_captcha_enqueue_admin_assets' );
