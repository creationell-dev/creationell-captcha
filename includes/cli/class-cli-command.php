<?php
/**
 * Top-level WP-CLI commands for CreaCaptcha.
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
 * Inspects and controls CreaCaptcha from the command line.
 */
class Command {

    /**
     * Shows the operational status: kill-switch, enabled modules, list sizes.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha status
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function status( $args, $assoc_args ): void {
        $settings = creationell_captcha_get_settings();
        $format   = $assoc_args['format'] ?? 'table';

        $on = static function ( $value ): string {
            return $value ? 'an' : 'aus';
        };

        $rows = [
            [
                'feld' => 'Kill-Switch (CREATIONELL_CAPTCHA_DISABLE)',
                'wert' => creationell_captcha_is_disabled() ? 'AKTIV — Plugin global deaktiviert' : 'inaktiv',
            ],
            [ 'feld' => 'Interceptor', 'wert' => $on( $settings['interceptor_enabled'] ) ],
            [ 'feld' => 'Firewall', 'wert' => $on( $settings['firewall_enabled'] ) ],
            [ 'feld' => 'Rate-Limiting', 'wert' => $on( $settings['ratelimit_enabled'] ) ],
            [ 'feld' => 'Under-Attack-Modus', 'wert' => $on( $settings['underattack_enabled'] ) ],
            [ 'feld' => 'Event-Log', 'wert' => $on( $settings['analytics_event_log'] ) ],
            [ 'feld' => 'E-Mail-Obfuskation', 'wert' => $on( $settings['obfuscate_emails'] ) ],
            [ 'feld' => 'Schutz: Kommentare', 'wert' => $on( $settings['protect_comments'] ) ],
            [ 'feld' => 'Schutz: Login', 'wert' => $on( $settings['protect_login'] ) ],
            [ 'feld' => 'Schutz: Registrierung', 'wert' => $on( $settings['protect_registration'] ) ],
            [ 'feld' => 'Schutz: Passwort-Reset', 'wert' => $on( $settings['protect_password_reset'] ) ],
            [ 'feld' => 'Schutz: CF7', 'wert' => $on( $settings['protect_cf7'] ) ],
            [ 'feld' => 'Schutz: Forminator', 'wert' => $on( $settings['protect_forminator'] ) ],
            [ 'feld' => 'Schutz: WPForms', 'wert' => $on( $settings['protect_wpforms'] ) ],
            [ 'feld' => 'Schutz: WooCommerce', 'wert' => $on( $settings['protect_woocommerce'] ) ],
            [
                'feld' => '… Checkout / Login / Registr. / Lost-PW',
                'wert' => sprintf(
                    '%s · %s · %s · %s',
                    $on( $settings['protect_wc_checkout'] ),
                    $on( $settings['protect_wc_login'] ),
                    $on( $settings['protect_wc_registration'] ),
                    $on( $settings['protect_wc_lost_password'] )
                ),
            ],
            [ 'feld' => 'Widget-Anzeige', 'wert' => (string) ( $settings['widget_display'] ?? 'standard' ) ],
            [
                'feld' => 'Widget-Sprache',
                'wert' => ( function (): string {
                    $wp_locale = (string) get_locale();
                    $resolved  = creationell_captcha_resolve_widget_locale();
                    return null === $resolved
                        ? sprintf( 'auto (%s nicht im Vendor-Set — Widget fällt auf EN)', $wp_locale )
                        : sprintf( '%s (aus %s)', $resolved, $wp_locale );
                } )(),
            ],
            [
                'feld' => 'Code-Challenge',
                'wert' => ( ! empty( $settings['code_challenge_enabled'] ) )
                    ? ( extension_loaded( 'gd' ) ? 'an' : 'inaktiv (kein GD)' )
                    : 'aus',
            ],
            [ 'feld' => 'Proxy-Modus (hinter Reverse-Proxy/CDN)', 'wert' => $on( $settings['firewall_behind_proxy'] ) ],
            [
                'feld' => 'CF-Trust / CF-Auto-Refresh',
                'wert' => sprintf(
                    '%s / %s',
                    $on( $settings['firewall_trust_cloudflare'] ),
                    $on( $settings['firewall_cloudflare_auto_refresh'] )
                ),
            ],
            [ 'feld' => 'IP-Anonymisierung (Event-Log)', 'wert' => $on( $settings['analytics_anonymize_ip'] ) ],
            [ 'feld' => 'IP-Blockliste', 'wert' => count( (array) $settings['firewall_ip_block'] ) . ' Einträge' ],
            [ 'feld' => 'IP-Erlaubnisliste', 'wert' => count( (array) $settings['firewall_ip_allow'] ) . ' Einträge' ],
            [ 'feld' => 'User-Agent-Blockliste', 'wert' => count( (array) $settings['firewall_ua_block'] ) . ' Einträge' ],
            [ 'feld' => 'Interceptor-Pfade', 'wert' => count( (array) $settings['interceptor_paths'] ) . ' Einträge' ],
            [ 'feld' => 'Vertrauenswürdige Proxies', 'wert' => count( (array) ( $settings['firewall_trusted_proxies'] ?? [] ) ) . ' Einträge' ],
            [ 'feld' => 'Bypass-UA-Liste', 'wert' => count( (array) ( $settings['bypass_ua_allow'] ?? [] ) ) . ' Einträge' ],
            [ 'feld' => 'Bypass-Cookies', 'wert' => count( (array) ( $settings['bypass_cookies'] ?? [] ) ) . ' Einträge' ],
            [ 'feld' => 'Geschützte Aktionen', 'wert' => count( (array) ( $settings['interceptor_actions'] ?? [] ) ) . ' Einträge' ],
            [ 'feld' => 'Inject-Pfade', 'wert' => count( (array) ( $settings['interceptor_inject_paths'] ?? [] ) ) . ' Einträge' ],
            [ 'feld' => 'Code-Challenge-Watchlist', 'wert' => count( (array) ( $settings['code_challenge_watchlist'] ?? [] ) ) . ' Einträge' ],
        ];

        \WP_CLI\Utils\format_items( $format, $rows, [ 'feld', 'wert' ] );
    }

    /**
     * Shows environment and diagnostic information.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha info
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function info( $args, $assoc_args ): void {
        $format       = $assoc_args['format'] ?? 'table';
        $settings     = creationell_captcha_get_settings();
        $analytics    = creationell_captcha_analytics();
        $secrets      = get_option( 'creationell_captcha_secrets', [] );
        $has_secrets  = is_array( $secrets ) && ! empty( $secrets['signature'] ) && ! empty( $secrets['key_signature'] );
        $table_exists = $analytics->table_exists();

        $rows = [
            [ 'feld' => 'Plugin-Version', 'wert' => CREATIONELL_CAPTCHA_VERSION ],
            [ 'feld' => 'DB-Versions-Option', 'wert' => (string) get_option( 'creationell_captcha_version', '—' ) ],
            [ 'feld' => 'PHP-Version', 'wert' => PHP_VERSION ],
            [ 'feld' => 'WordPress-Version', 'wert' => (string) get_bloginfo( 'version' ) ],
            [ 'feld' => 'Algorithmus', 'wert' => (string) $settings['algorithm'] ],
            [ 'feld' => 'Sodium verfügbar', 'wert' => creationell_captcha_sodium_available() ? 'ja' : 'nein' ],
            [ 'feld' => 'HMAC-Secrets vorhanden', 'wert' => $has_secrets ? 'ja' : 'nein' ],
            [ 'feld' => 'Event-Log-Tabelle', 'wert' => $table_exists ? 'vorhanden' : 'nicht vorhanden' ],
            [ 'feld' => 'Event-Log-Zeilen', 'wert' => $table_exists ? (string) $analytics->count_events( [] ) : '—' ],
            [ 'feld' => 'Plugin-Pfad', 'wert' => CREATIONELL_CAPTCHA_PLUGIN_PATH ],
        ];

        \WP_CLI\Utils\format_items( $format, $rows, [ 'feld', 'wert' ] );
    }

    /**
     * Shows the analytics counters per event type.
     *
     * ## OPTIONS
     *
     * [--window=<window>]
     * : Time window: 24h, 7d, 30d, 90d or all. Default: all.
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha stats --window=7d
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function stats( $args, $assoc_args ): void {
        $format    = $assoc_args['format'] ?? 'table';
        $window    = $assoc_args['window'] ?? 'all';
        $analytics = creationell_captcha_analytics();
        $labels    = creationell_captcha_analytics_labels();
        $daily     = $analytics->get_daily_counts();
        $hourly    = $analytics->get_hourly_counts();

        $windows = [
            '24h' => creationell_captcha_sum_recent_hours( $hourly, 24 ),
            '7d'  => creationell_captcha_sum_recent_days( $daily, 7 ),
            '30d' => creationell_captcha_sum_recent_days( $daily, 30 ),
            '90d' => creationell_captcha_sum_recent_days( $daily, 90 ),
        ];

        if ( 'all' !== $window ) {
            if ( ! isset( $windows[ $window ] ) ) {
                WP_CLI::error( 'Ungültiges Zeitfenster. Erlaubt: 24h, 7d, 30d, 90d, all.' );
            }
            $windows = [ $window => $windows[ $window ] ];
        }

        $rows = [];
        foreach ( $labels as $type => $label ) {
            $row = [ 'ereignis' => $label ];
            foreach ( $windows as $win_key => $totals ) {
                $row[ $win_key ] = (int) ( $totals[ $type ] ?? 0 );
            }
            $rows[] = $row;
        }

        \WP_CLI\Utils\format_items( $format, $rows, array_merge( [ 'ereignis' ], array_keys( $windows ) ) );
    }

    /**
     * Enables a CreaCaptcha module.
     *
     * Exit-Code 1, wenn der Schalter nicht gesetzt werden konnte — etwa weil
     * das zugehörige Formular-Plugin nicht aktiv ist und die Einstellung
     * deshalb gar nicht existiert (früher: Erfolgsmeldung mit Exit 0, ohne dass
     * sich etwas änderte).
     *
     * ## OPTIONS
     *
     * <feature>
     * : Feature to enable: interceptor, firewall, ratelimit, underattack, event-log, email-obfuscation, code-challenge, comments, login, registration, password-reset, cf7, forminator, wpforms, woocommerce, wc-checkout, wc-login, wc-registration, wc-lost-password.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha enable firewall
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function enable( $args, $assoc_args ): void {
        $this->set_feature( (string) ( $args[0] ?? '' ), true );
    }

    /**
     * Disables a CreaCaptcha module.
     *
     * Exit-Code 1, wenn der Schalter nicht gesetzt werden konnte — siehe
     * `enable`.
     *
     * ## OPTIONS
     *
     * <feature>
     * : Feature to disable: interceptor, firewall, ratelimit, underattack, event-log, email-obfuscation, code-challenge, comments, login, registration, password-reset, cf7, forminator, wpforms, woocommerce, wc-checkout, wc-login, wc-registration, wc-lost-password.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha disable underattack
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function disable( $args, $assoc_args ): void {
        $this->set_feature( (string) ( $args[0] ?? '' ), false );
    }

    /**
     * Repairs a CreaCaptcha installation: secrets, event-log table, missing
     * default keys, version option.
     *
     * Grenze des Werkzeugs (CLI-10): Repariert wird, was FEHLT — ein Secret,
     * die Event-Log-Tabelle, ein Einstellungsschlüssel, die Versions-Option.
     * Der INHALT vorhandener Einstellungswerte wird nicht gegen die
     * Feldspezifikation geprüft; ein an den Plugin-Schreibwegen vorbei
     * gesetzter Wert (`wp option patch`, direkter DB-Zugriff) überlebt
     * `repair` und wird erst beim nächsten regulären Speichern normalisiert
     * (Einstellungsseite speichern oder `wp creacaptcha settings set <key>
     * <wert>`).
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha repair
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function repair( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Reparatur durchführen?', $assoc_args );

        $done = [];

        // 1. HMAC secrets.
        $secrets = get_option( 'creationell_captcha_secrets', [] );
        if ( ! is_array( $secrets ) || empty( $secrets['signature'] ) || empty( $secrets['key_signature'] ) ) {
            creationell_captcha_generate_secrets();
            $done[] = 'HMAC-Secrets neu erzeugt.';
        }

        // 2. Event-log table.
        $settings  = creationell_captcha_get_settings();
        $analytics = creationell_captcha_analytics();
        if ( ! empty( $settings['analytics_event_log'] ) && ! $analytics->table_exists() ) {
            $analytics->ensure_table();
            $done[] = 'Event-Log-Tabelle angelegt.';
        }

        // 3. Missing default keys.
        $stored = get_option( 'creationell_captcha_settings', [] );
        if ( ! is_array( $stored ) ) {
            $stored = [];
        }
        $defaults = creationell_captcha_get_default_settings();
        $missing  = array_diff_key( $defaults, $stored );
        if ( ! empty( $missing ) ) {
            creationell_captcha_store_settings( creationell_captcha_sanitize_settings( $stored + $defaults ) );
            $done[] = sprintf( '%d fehlende(r) Einstellungsschlüssel ergänzt.', count( $missing ) );
        }

        // 4. Version option.
        if ( (string) get_option( 'creationell_captcha_version', '' ) !== CREATIONELL_CAPTCHA_VERSION ) {
            update_option( 'creationell_captcha_version', CREATIONELL_CAPTCHA_VERSION );
            $done[] = 'Versions-Option synchronisiert.';
        }

        if ( empty( $done ) ) {
            // CLI-10: „Nichts zu reparieren" hieß bisher implizit „alles in
            // Ordnung". Repariert wird aber nur, was fehlt — der Inhalt
            // vorhandener Werte wird nicht geprüft. Die Meldung sagt jetzt,
            // was sie belegt.
            WP_CLI::success( 'Nichts zu reparieren: Secrets, Event-Log-Tabelle, Einstellungsschlüssel und Versions-Option sind vollständig. Der Inhalt der gespeicherten Einstellungswerte wird dabei nicht geprüft.' );
            return;
        }

        foreach ( $done as $line ) {
            WP_CLI::log( ' • ' . $line );
        }
        WP_CLI::success( sprintf( '%d Reparatur(en) durchgeführt.', count( $done ) ) );
    }

    /**
     * Maps CLI feature names to their boolean setting key.
     *
     * @return array<string, string>
     */
    private function feature_map(): array {
        return [
            'interceptor'        => 'interceptor_enabled',
            'firewall'           => 'firewall_enabled',
            'ratelimit'          => 'ratelimit_enabled',
            'underattack'        => 'underattack_enabled',
            'event-log'          => 'analytics_event_log',
            'email-obfuscation'  => 'obfuscate_emails',
            'code-challenge'     => 'code_challenge_enabled',
            'comments'           => 'protect_comments',
            'login'              => 'protect_login',
            'registration'       => 'protect_registration',
            'password-reset'     => 'protect_password_reset',
            'cf7'                => 'protect_cf7',
            'forminator'         => 'protect_forminator',
            'wpforms'            => 'protect_wpforms',
            'woocommerce'        => 'protect_woocommerce',
            'wc-checkout'        => 'protect_wc_checkout',
            'wc-login'           => 'protect_wc_login',
            'wc-registration'    => 'protect_wc_registration',
            'wc-lost-password'   => 'protect_wc_lost_password',
        ];
    }

    /**
     * Toggles a feature's boolean setting.
     *
     * @param string $feature CLI feature name.
     * @param bool   $on      Target state.
     */
    private function set_feature( string $feature, bool $on ): void {
        $map = $this->feature_map();
        if ( ! isset( $map[ $feature ] ) ) {
            WP_CLI::error(
                'Unbekanntes Feature. Gültige Werte: ' . implode( ', ', array_keys( $map ) ) . '.'
            );
        }

        $key = $map[ $feature ];

        // CLI-3: Die Feldspezifikation enthält die protect_*-Schalter der
        // Formular-Plugins nur, solange das jeweilige Plugin aktiv ist
        // (class_exists-Gates in creationell_captcha_settings_fields()). Fehlt
        // der Schlüssel dort, überspringt ihn der Sanitizer-Feld-Loop; danach
        // stellt entweder die Preserve-Schleife den Altwert aus der Option
        // wieder her oder der Schlüssel fehlt im Ergebnis ganz und
        // creationell_captcha_get_settings() liefert wieder den Default. In
        // beiden Fällen war der Schreibvorgang ein No-Op, während die CLI
        // Erfolg meldete. Vorher benennen statt hinterher raten.
        $fields = creationell_captcha_settings_fields();
        if ( ! isset( $fields[ $key ] ) ) {
            WP_CLI::error(
                sprintf(
                    'Feature „%s" (Schlüssel „%s") ist derzeit nicht setzbar: die Einstellungsspezifikation kennt den Schlüssel nicht. Bei den Formular-Plugin-Schaltern ist die Ursache in aller Regel, dass das zugehörige Plugin nicht aktiv ist. Der gespeicherte Wert bleibt unverändert (%s).',
                    $feature,
                    $key,
                    ! empty( creationell_captcha_get_settings()[ $key ] ) ? 'an' : 'aus'
                )
            );
        }

        $settings         = creationell_captcha_get_settings();
        $settings[ $key ] = $on;
        creationell_captcha_store_settings(
            creationell_captcha_sanitize_settings( $settings, \CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC )
        );

        // CLI-3: Rückprüfung am frisch gelesenen Stand. Der Vorab-Check oben
        // deckt die bekannte Ursache ab; diese Prüfung ist ein Netz für jede
        // andere — sie fragt nicht, WARUM ein Wert verworfen worden sein
        // könnte, sondern nur, ob er nach dem Schreiben dasteht. Auf dem
        // heutigen Stand löst sie kein bekannter Pfad aus; genau deshalb steht
        // sie hier: der Befund ist, dass dieses Kommando Erfolg meldete, ohne
        // je nachgesehen zu haben.
        $actual = ! empty( creationell_captcha_get_settings( true )[ $key ] );
        if ( $actual !== $on ) {
            WP_CLI::error(
                sprintf(
                    'Feature „%s" konnte nicht %s werden — der Wert wurde beim Speichern verworfen und steht weiterhin auf „%s".',
                    $feature,
                    $on ? 'aktiviert' : 'deaktiviert',
                    $actual ? 'an' : 'aus'
                )
            );
        }

        // Nachlese N2 hat die Kompensation für den Schreibvorgang OHNE
        // Wertänderung hier eingeführt (WordPress feuert
        // update_option_{$option} nur bei echter Änderung, und seit E3b hängt
        // die Tabellenanlage ausschliesslich an diesem Hook — `wp creacaptcha
        // enable event-log` als Reparaturversuch bei bereits eingeschaltetem
        // Log lief also ins Leere). Nachlese N6 hat sie eine Ebene tiefer
        // gelegt: creationell_captcha_store_settings() oben ruft
        // creationell_captcha_sync_event_log_table() für JEDEN
        // Plugin-Schreibweg nach, nicht nur für diesen einen. Ein zweiter
        // Aufruf an dieser Stelle wäre nur noch Wiederholung.

        WP_CLI::success(
            sprintf( 'Feature „%s" ist jetzt %s.', $feature, $on ? 'aktiviert' : 'deaktiviert' )
        );
    }
}
