<?php
/**
 * Shared settings-management service.
 *
 * Export, import, reset and "load defaults" — used by both the backend
 * "Werkzeuge" page and the WP-CLI commands.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Schema version of the settings-export format.
 */
const CREATIONELL_CAPTCHA_EXPORT_SCHEMA = 1;

/**
 * Setting keys whose value is a list (every `textarea` field).
 *
 * Derived from the field specification so the list never drifts. "Load
 * defaults" preserves these keys; "reset" clears them.
 *
 * @return array<int, string>
 */
function creationell_captcha_list_setting_keys(): array {
    $keys = [];
    foreach ( creationell_captcha_settings_fields() as $key => $field ) {
        if ( isset( $field['type'] ) && 'textarea' === $field['type'] ) {
            $keys[] = $key;
        }
    }

    return $keys;
}

/**
 * Builds the settings-export payload.
 *
 * The HMAC secrets are deliberately excluded — they must never leave the site.
 *
 * @return array<string, mixed>
 */
function creationell_captcha_export_settings(): array {
    return [
        'plugin'         => 'creationell-captcha',
        'type'           => 'settings-export',
        'schema'         => CREATIONELL_CAPTCHA_EXPORT_SCHEMA,
        'plugin_version' => CREATIONELL_CAPTCHA_VERSION,
        'exported_at'    => gmdate( 'c' ),
        'site_url'       => home_url(),
        'settings'       => creationell_captcha_get_settings(),
    ];
}

/**
 * Validates and applies a settings-export payload.
 *
 * The `settings` array is run through creationell_captcha_sanitize_settings(),
 * so the same guarantees as the settings form apply: whitelisted selects,
 * clamped numbers, bounded lists, unknown keys dropped, missing keys defaulted.
 *
 * @param array<string, mixed> $payload Decoded export payload.
 * @return array<string, mixed>|WP_Error On success: { imported, version_notice }.
 */
function creationell_captcha_import_settings( array $payload ): array|WP_Error {
    if ( ( $payload['plugin'] ?? '' ) !== 'creationell-captcha'
        || ( $payload['type'] ?? '' ) !== 'settings-export'
    ) {
        return new WP_Error(
            'creationell_captcha_import_invalid',
            __( 'Die Datei ist keine gültige CreaCaptcha-Einstellungsdatei.', 'creationell-captcha' )
        );
    }

    if ( (int) ( $payload['schema'] ?? 0 ) !== CREATIONELL_CAPTCHA_EXPORT_SCHEMA ) {
        return new WP_Error(
            'creationell_captcha_import_schema',
            __( 'Das Format dieser Einstellungsdatei wird von dieser Plugin-Version nicht unterstützt.', 'creationell-captcha' )
        );
    }

    if ( ! isset( $payload['settings'] ) || ! is_array( $payload['settings'] ) ) {
        return new WP_Error(
            'creationell_captcha_import_empty',
            __( 'Die Einstellungsdatei enthält keine Einstellungen.', 'creationell-captcha' )
        );
    }

    $clean = creationell_captcha_sanitize_settings( $payload['settings'] );
    update_option( 'creationell_captcha_settings', $clean );

    $version_notice = '';
    $file_version   = (string) ( $payload['plugin_version'] ?? '' );
    if ( '' !== $file_version && $file_version !== CREATIONELL_CAPTCHA_VERSION ) {
        $version_notice = sprintf(
            /* translators: 1: plugin version the file was exported with, 2: current plugin version. */
            __( 'Hinweis: Die Datei wurde mit Version %1$s erstellt, aktuell läuft %2$s.', 'creationell-captcha' ),
            $file_version,
            CREATIONELL_CAPTCHA_VERSION
        );
    }

    return [
        'imported'       => $clean,
        'version_notice' => $version_notice,
    ];
}

/**
 * Full factory reset: writes the complete default settings array, which also
 * empties every list. Secrets, analytics counters and the event log are
 * left untouched.
 */
function creationell_captcha_reset_settings(): void {
    update_option( 'creationell_captcha_settings', creationell_captcha_get_default_settings() );
}

/**
 * Resets every non-list setting to its default while preserving the current
 * list values (IP block/allow, UA block, interceptor paths).
 */
function creationell_captcha_load_default_settings(): void {
    $defaults = creationell_captcha_get_default_settings();
    $current  = creationell_captcha_get_settings();

    foreach ( creationell_captcha_list_setting_keys() as $key ) {
        if ( array_key_exists( $key, $current ) ) {
            $defaults[ $key ] = $current[ $key ];
        }
    }

    update_option( 'creationell_captcha_settings', $defaults );
}
