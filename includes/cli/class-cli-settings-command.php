<?php
/**
 * WP-CLI "settings" subcommands for CreaCaptcha.
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
 * Reads, writes, exports, imports and resets CreaCaptcha settings.
 */
class Settings_Command {

    /**
     * Lists all settings as key/value pairs.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings list
     *
     * @subcommand list
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function list_settings( $args, $assoc_args ): void {
        $format   = $assoc_args['format'] ?? 'table';
        $settings = creationell_captcha_get_settings();

        $rows = [];
        foreach ( $settings as $key => $value ) {
            $rows[] = [
                'schluessel' => (string) $key,
                'wert'       => $this->stringify( $value ),
            ];
        }

        \WP_CLI\Utils\format_items( $format, $rows, [ 'schluessel', 'wert' ] );
    }

    /**
     * Prints one setting value.
     *
     * ## OPTIONS
     *
     * <key>
     * : The setting key.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings get difficulty
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function get( $args, $assoc_args ): void {
        $key      = (string) ( $args[0] ?? '' );
        $settings = creationell_captcha_get_settings();

        if ( ! array_key_exists( $key, $settings ) ) {
            WP_CLI::error( sprintf( 'Unbekannter Schlüssel „%s".', $key ) );
        }

        WP_CLI::line( $this->stringify( $settings[ $key ] ) );
    }

    /**
     * Sets one setting value.
     *
     * ## OPTIONS
     *
     * <key>
     * : The setting key.
     *
     * <value>
     * : The new value. Checkboxes accept true/false/1/0/yes/no/on/off.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings set difficulty high
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function set( $args, $assoc_args ): void {
        $key   = (string) ( $args[0] ?? '' );
        $value = (string) ( $args[1] ?? '' );

        $fields = creationell_captcha_settings_fields();
        if ( ! isset( $fields[ $key ] ) ) {
            WP_CLI::error( sprintf( 'Unbekannter oder nicht setzbarer Schlüssel „%s".', $key ) );
        }

        $field = $fields[ $key ];
        if ( 'textarea' === ( $field['type'] ?? '' ) ) {
            WP_CLI::error(
                sprintf(
                    'Der Schlüssel „%s" ist eine Liste. Bitte die Befehle blocklist / allowlist / ua-blocklist / paths / trusted-proxies / bypass-ua / bypass-cookies / actions / inject-paths / watchlist verwenden.',
                    $key
                )
            );
        }

        $settings = creationell_captcha_get_settings();

        switch ( $field['type'] ) {
            case 'checkbox':
                $settings[ $key ] = $this->parse_bool( $value );
                break;
            case 'number':
                if ( ! is_numeric( $value ) ) {
                    WP_CLI::error( sprintf( 'Der Schlüssel „%s" erwartet einen numerischen Wert.', $key ) );
                }
                $settings[ $key ] = (int) $value;
                break;
            case 'select':
                if ( ! array_key_exists( $value, $field['options'] ?? [] ) ) {
                    WP_CLI::error(
                        'Ungültiger Wert. Erlaubt: ' . implode( ', ', array_keys( $field['options'] ?? [] ) ) . '.'
                    );
                }
                $settings[ $key ] = $value;
                break;
            case 'text':
            case 'color':
            case 'textblock':
                $settings[ $key ] = $value;
                break;
            default:
                WP_CLI::error( 'Dieser Feldtyp wird vom set-Befehl nicht unterstützt.' );
        }

        $clean = creationell_captcha_sanitize_settings( $settings );
        $input_was_non_empty = '' !== trim( $value );
        $stored_is_empty     = ( '' === (string) ( $clean[ $key ] ?? '' ) );
        if ( in_array( $field['type'], [ 'color', 'textblock' ], true ) && $input_was_non_empty && $stored_is_empty ) {
            WP_CLI::warning(
                sprintf(
                    'Wert für „%s" wurde von der Sanitisierung verworfen (ungültiges JSON bei widget_strings_override oder ungültiger Hex-Wert bei widget_primary_color).',
                    $key
                )
            );
        }
        update_option( 'creationell_captcha_settings', $clean );

        WP_CLI::success( sprintf( '%s = %s', $key, $this->stringify( $clean[ $key ] ) ) );
    }

    /**
     * Exports all settings as JSON.
     *
     * ## OPTIONS
     *
     * [--file=<path>]
     * : Write to this file instead of STDOUT.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings export --file=backup.json
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function export( $args, $assoc_args ): void {
        $json = wp_json_encode(
            creationell_captcha_export_settings(),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        if ( false === $json ) {
            WP_CLI::error( 'Einstellungen konnten nicht als JSON kodiert werden.' );
        }

        if ( isset( $assoc_args['file'] ) ) {
            $path = (string) $assoc_args['file'];
            if ( false === file_put_contents( $path, $json . "\n" ) ) {
                WP_CLI::error( sprintf( 'Datei „%s" konnte nicht geschrieben werden.', $path ) );
            }
            WP_CLI::success( sprintf( 'Einstellungen nach „%s" exportiert.', $path ) );
            return;
        }

        WP_CLI::line( (string) $json );
    }

    /**
     * Imports settings from a JSON file.
     *
     * ## OPTIONS
     *
     * <file>
     * : Path to a settings-export JSON file.
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings import backup.json
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function import( $args, $assoc_args ): void {
        $path = (string) ( $args[0] ?? '' );
        if ( '' === $path || ! is_readable( $path ) ) {
            WP_CLI::error( sprintf( 'Datei „%s" nicht lesbar.', $path ) );
        }

        $raw = file_get_contents( $path );
        if ( false === $raw ) {
            WP_CLI::error( sprintf( 'Datei „%s" konnte nicht gelesen werden.', $path ) );
        }

        $payload = json_decode( $raw, true );
        if ( ! is_array( $payload ) ) {
            WP_CLI::error( 'Die Datei ist kein gültiges JSON.' );
        }

        WP_CLI::confirm( 'Die aktuelle Konfiguration wird ersetzt. Fortfahren?', $assoc_args );

        $result = creationell_captcha_import_settings( $payload );
        if ( is_wp_error( $result ) ) {
            WP_CLI::error( $result->get_error_message() );
        }

        if ( ! empty( $result['version_notice'] ) ) {
            WP_CLI::warning( $result['version_notice'] );
        }
        WP_CLI::success( 'Einstellungen importiert.' );
    }

    /**
     * Resets every setting to its default — including emptying all lists.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings reset --yes
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function reset( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Alle Einstellungen inklusive der Listen auf Werkseinstellungen zurücksetzen?', $assoc_args );
        creationell_captcha_reset_settings();
        WP_CLI::success( 'Auf Werkseinstellungen zurückgesetzt.' );
    }

    /**
     * Resets configuration values to default but keeps the lists.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings load-defaults --yes
     *
     * @subcommand load-defaults
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function load_defaults( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Alle Konfigurationswerte auf Standard zurücksetzen? Die Listen bleiben erhalten.', $assoc_args );
        creationell_captcha_load_default_settings();
        WP_CLI::success( 'Standardwerte geladen; die Listen blieben erhalten.' );
    }

    /**
     * Converts a setting value to a printable string.
     *
     * @param mixed $value Raw setting value.
     */
    private function stringify( $value ): string {
        if ( is_bool( $value ) ) {
            return $value ? 'true' : 'false';
        }
        if ( is_array( $value ) ) {
            return implode( ', ', array_map( 'strval', $value ) );
        }

        return (string) $value;
    }

    /**
     * Parses a boolean-ish CLI string.
     *
     * @param string $value Raw value.
     */
    private function parse_bool( string $value ): bool {
        return in_array( strtolower( trim( $value ) ), [ '1', 'true', 'yes', 'on' ], true );
    }
}
