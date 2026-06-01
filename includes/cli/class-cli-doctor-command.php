<?php
/**
 * WP-CLI: runs a diagnostic checklist over the CreaCaptcha installation.
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
 * `wp creacaptcha doctor`
 */
class Doctor_Command {

    /**
     * Runs the diagnostic checklist and prints a status table.
     *
     * Exit code 1 if at least one check is `error`, 0 otherwise.
     *
     * Third-party modules can extend the list via the
     * `creationell_captcha_doctor_checks` filter. Filter receives the array
     * of checks (each `[check => string, status => 'ok'|'warn'|'error',
     * meldung => string]`) and must return the same shape.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha doctor
     *
     * @when after_wp_load
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function __invoke( array $args, array $assoc_args ): void {
        $format = $assoc_args['format'] ?? 'table';

        if ( ! function_exists( 'is_plugin_active' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $settings = creationell_captcha_get_settings();

        $checks = [];

        // 1. Vendored library — Strauss writes to lib/<package-path>/src/, the
        //    canonical signal that the build has been run is lib/autoload.php.
        $lib_autoload = CREATIONELL_CAPTCHA_PLUGIN_PATH . 'lib/autoload.php';
        $checks[] = file_exists( $lib_autoload )
            ? [ 'check' => 'Vendored Library', 'status' => 'ok', 'meldung' => dirname( $lib_autoload ) ]
            : [ 'check' => 'Vendored Library', 'status' => 'error', 'meldung' => sprintf( 'Datei fehlt: %s — „composer install" ausführen.', $lib_autoload ) ];

        // 2. HMAC secrets.
        $secrets     = get_option( 'creationell_captcha_secrets', [] );
        $has_secrets = is_array( $secrets ) && ! empty( $secrets['signature'] ) && ! empty( $secrets['key_signature'] );
        $checks[]    = $has_secrets
            ? [ 'check' => 'HMAC-Secrets', 'status' => 'ok', 'meldung' => 'gesetzt' ]
            : [ 'check' => 'HMAC-Secrets', 'status' => 'error', 'meldung' => 'Option creationell_captcha_secrets fehlt oder leer — `wp creacaptcha repair` ausführen.' ];

        // 3. Event-log table.
        if ( ! empty( $settings['analytics_event_log'] ) ) {
            $analytics    = creationell_captcha_analytics();
            $table_exists = $analytics->table_exists();
            $checks[]     = $table_exists
                ? [ 'check' => 'Event-Log-Tabelle', 'status' => 'ok', 'meldung' => 'vorhanden' ]
                : [ 'check' => 'Event-Log-Tabelle', 'status' => 'error', 'meldung' => 'Tabelle fehlt obwohl Event-Log aktiv — `wp creacaptcha repair` ausführen.' ];
        } else {
            $checks[] = [ 'check' => 'Event-Log-Tabelle', 'status' => 'ok', 'meldung' => 'übersprungen (Event-Log aus)' ];
        }

        // 4. Cloudflare refresh cron.
        if ( ! empty( $settings['firewall_cloudflare_auto_refresh'] ) ) {
            $next = wp_next_scheduled( 'creationell_captcha_refresh_cloudflare_ips' );
            $checks[] = false !== $next
                ? [ 'check' => 'Cloudflare-Refresh-Cron', 'status' => 'ok', 'meldung' => sprintf( 'geplant für %s UTC', gmdate( 'Y-m-d H:i:s', (int) $next ) ) ]
                : [ 'check' => 'Cloudflare-Refresh-Cron', 'status' => 'error', 'meldung' => 'auto-refresh aktiv, aber kein Cron geplant — Settings einmal speichern oder `wp cron event schedule` aufrufen.' ];
        } else {
            $checks[] = [ 'check' => 'Cloudflare-Refresh-Cron', 'status' => 'ok', 'meldung' => 'übersprungen (auto-refresh aus)' ];
        }

        // 5. Kill switch.
        $checks[] = creationell_captcha_is_disabled()
            ? [ 'check' => 'Kill-Switch', 'status' => 'warn', 'meldung' => 'CREATIONELL_CAPTCHA_DISABLE ist truthy — Plugin global deaktiviert.' ]
            : [ 'check' => 'Kill-Switch', 'status' => 'ok', 'meldung' => 'inaktiv' ];

        // 6. Conflicting captcha plugins.
        $conflicts = [
            'altcha/altcha.php'                                               => 'ALTCHA (offizielles Plugin)',
            'recaptcha/recaptcha.php'                                         => 'reCAPTCHA',
            'hcaptcha-for-forms-and-more/hcaptcha.php'                        => 'hCaptcha for Forms and More',
            'simple-cloudflare-turnstile/simple-cloudflare-turnstile.php'     => 'Simple Cloudflare Turnstile',
        ];
        $active_conflicts = [];
        foreach ( $conflicts as $slug => $label ) {
            if ( is_plugin_active( $slug ) ) {
                $active_conflicts[] = $label;
            }
        }
        $checks[] = empty( $active_conflicts )
            ? [ 'check' => 'Captcha-Plugin-Konflikte', 'status' => 'ok', 'meldung' => 'keine bekannten Captcha-Plugins aktiv' ]
            : [ 'check' => 'Captcha-Plugin-Konflikte', 'status' => 'warn', 'meldung' => 'aktiv: ' . implode( ', ', $active_conflicts ) ];

        // 7. PHP version.
        $checks[] = PHP_VERSION_ID >= 80300
            ? [ 'check' => 'PHP-Version', 'status' => 'ok', 'meldung' => PHP_VERSION ]
            : [ 'check' => 'PHP-Version', 'status' => 'error', 'meldung' => sprintf( 'PHP %s — erfordert ≥ 8.3', PHP_VERSION ) ];

        // 7b. Sodium-Extension (für Argon2id-Algorithmus erforderlich).
        if ( 'argon2id' === ( $settings['algorithm'] ?? '' ) ) {
            $checks[] = creationell_captcha_sodium_available()
                ? [ 'check' => 'Sodium-Extension', 'status' => 'ok', 'meldung' => 'verfügbar (für Argon2id)' ]
                : [ 'check' => 'Sodium-Extension', 'status' => 'error', 'meldung' => 'fehlt — Argon2id ist konfiguriert, die Engine wird beim Lösen fehlschlagen. PBKDF2 wählen oder ext-sodium installieren.' ];
        } else {
            $checks[] = [ 'check' => 'Sodium-Extension', 'status' => 'ok', 'meldung' => 'übersprungen (Algorithmus ist PBKDF2)' ];
        }

        // 8. Cloudflare cache age.
        if ( ! empty( $settings['firewall_trust_cloudflare'] ) ) {
            $cached     = get_option( 'creationell_captcha_cloudflare_ips', [] );
            $fetched_at = is_array( $cached ) ? (int) ( $cached['fetched_at'] ?? 0 ) : 0;
            if ( $fetched_at <= 0 ) {
                $checks[] = [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'warn', 'meldung' => 'kein Cache vorhanden — `wp creacaptcha cloudflare refresh` ausführen.' ];
            } else {
                $age      = time() - $fetched_at;
                $checks[] = $age > DAY_IN_SECONDS
                    ? [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'warn', 'meldung' => sprintf( 'älter als 24 h (Alter: %s)', human_time_diff( $fetched_at, time() ) ) ]
                    : [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'ok', 'meldung' => sprintf( 'frisch (Alter: %s)', human_time_diff( $fetched_at, time() ) ) ];
            }
        } else {
            $checks[] = [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'ok', 'meldung' => 'übersprungen (firewall_trust_cloudflare aus)' ];
        }

        // 9. Settings defaults completeness.
        $defaults = creationell_captcha_get_default_settings();
        $stored   = get_option( 'creationell_captcha_settings', [] );
        if ( ! is_array( $stored ) ) {
            $stored = [];
        }
        $missing  = array_diff_key( $defaults, $stored );
        $checks[] = empty( $missing )
            ? [ 'check' => 'Settings-Defaults', 'status' => 'ok', 'meldung' => 'vollständig' ]
            : [ 'check' => 'Settings-Defaults', 'status' => 'warn', 'meldung' => sprintf( '%d Schlüssel fehlen (%s) — `wp creacaptcha repair` ausführen.', count( $missing ), implode( ', ', array_slice( array_keys( $missing ), 0, 5 ) ) ) ];

        // 10. PHP-GD-Extension (für Code-Challenge erforderlich).
        if ( ! empty( $settings['code_challenge_enabled'] ) ) {
            $checks[] = extension_loaded( 'gd' )
                ? [ 'check' => 'PHP-GD-Extension', 'status' => 'ok', 'meldung' => 'verfügbar (für Code-Challenge)' ]
                : [ 'check' => 'PHP-GD-Extension', 'status' => 'error', 'meldung' => 'fehlt — Code-Challenge ist konfiguriert, aber das Bild kann nicht gerendert werden.' ];
        } else {
            $checks[] = [ 'check' => 'PHP-GD-Extension', 'status' => 'ok', 'meldung' => 'übersprungen (Code-Challenge aus)' ];
        }

        /**
         * Filters the doctor-checklist. Third-party modules can append their
         * own checks. Each entry must follow the shape
         * `['check' => string, 'status' => 'ok'|'warn'|'error', 'meldung' => string]`.
         */
        $checks = (array) apply_filters( 'creationell_captcha_doctor_checks', $checks );

        $has_error = false;
        foreach ( $checks as $row ) {
            if ( 'error' === ( $row['status'] ?? '' ) ) {
                $has_error = true;
                break;
            }
        }

        \WP_CLI\Utils\format_items( $format, $checks, [ 'check', 'status', 'meldung' ] );

        if ( $has_error ) {
            WP_CLI::halt( 1 );
        }
    }
}
