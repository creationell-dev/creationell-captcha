<?php
/**
 * WP-CLI "log" subcommands for CreaCaptcha.
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
 * Inspects and maintains the optional event-log table.
 */
class Log_Command {

    /**
     * Lists the most recent event-log rows.
     *
     * ## OPTIONS
     *
     * [--number=<n>]
     * : How many rows to show. Default: 20.
     *
     * [--type=<type>]
     * : Filter by event type (verified, failed, firewall, ratelimit, underattack, underattack_passed, challenge).
     *
     * [--fields=<fields>]
     * : Komma-Liste der anzuzeigenden Spalten. Default: created_at,event_type,ip,path.
     *   Verfügbare Spalten: id, created_at, event_type, ip, user_id, user_agent,
     *   referrer, path, plugin, action, form_id, interceptor, reason,
     *   verification_data, request_body.
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha log list --number=50 --type=firewall
     *     wp creacaptcha log list --fields=created_at,event_type,plugin,form_id
     *
     * @subcommand list
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function list_events( $args, $assoc_args ): void {
        $analytics = creationell_captcha_analytics();
        if ( ! $analytics->table_exists() ) {
            WP_CLI::warning( 'Die Event-Log-Tabelle existiert nicht — das Event-Log ist nicht aktiviert.' );
            return;
        }

        $number = max( 1, (int) ( $assoc_args['number'] ?? 20 ) );
        $format = $assoc_args['format'] ?? 'table';

        $filter = [
            'limit'  => $number,
            'offset' => 0,
        ];
        if ( isset( $assoc_args['type'] ) ) {
            $type  = (string) $assoc_args['type'];
            $types = array_keys( creationell_captcha_analytics_labels() );
            if ( ! in_array( $type, $types, true ) ) {
                WP_CLI::error( 'Ungültiger Ereignistyp. Erlaubt: ' . implode( ', ', $types ) . '.' );
            }
            $filter['event_type'] = $type;
        }

        $rows = $analytics->query_events( $filter );
        if ( empty( $rows ) ) {
            WP_CLI::log( 'Keine Ereignisse gefunden.' );
            return;
        }

        $default_fields = [ 'created_at', 'event_type', 'ip', 'path' ];

        $assoc_args['format'] = $format;
        $formatter            = new \WP_CLI\Formatter( $assoc_args, $default_fields );
        $formatter->display_items( $rows );
    }

    /**
     * Zeigt einen einzelnen Event-Log-Eintrag mit allen Spalten.
     *
     * ## OPTIONS
     *
     * <id>
     * : Die Event-ID aus der Spalte `id` in `log list`.
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv). Default: table.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha log show 42
     *     wp creacaptcha log show 42 --format=json
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function show( $args, $assoc_args ): void {
        $analytics = creationell_captcha_analytics();
        if ( ! $analytics->table_exists() ) {
            WP_CLI::error( 'Die Event-Log-Tabelle existiert nicht — das Event-Log ist nicht aktiviert.' );
        }

        $id = (int) ( $args[0] ?? 0 );
        if ( $id <= 0 ) {
            WP_CLI::error( 'Ungültige ID — erwartet wird eine positive Ganzzahl.' );
        }

        $rows = $analytics->query_events( [ 'id' => $id, 'limit' => 1 ] );
        if ( empty( $rows ) ) {
            WP_CLI::error( sprintf( 'Kein Event mit ID %d gefunden.', $id ) );
        }

        $row    = $rows[0];
        $format = $assoc_args['format'] ?? 'table';

        if ( in_array( $format, [ 'json', 'yaml', 'csv' ], true ) ) {
            \WP_CLI\Utils\format_items( $format, [ $row ], array_keys( $row ) );
            return;
        }

        // Default: Tabelle mit zwei Spalten (feld/wert), eine Zeile je Spalte.
        $kv_rows = [];
        foreach ( $row as $field => $value ) {
            $kv_rows[] = [
                'feld' => (string) $field,
                'wert' => ( '' === (string) $value ) ? '—' : (string) $value,
            ];
        }
        \WP_CLI\Utils\format_items( 'table', $kv_rows, [ 'feld', 'wert' ] );
    }

    /**
     * Empties the event-log table.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha log clear --yes
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function clear( $args, $assoc_args ): void {
        $analytics = creationell_captcha_analytics();
        if ( ! $analytics->table_exists() ) {
            WP_CLI::warning( 'Die Event-Log-Tabelle existiert nicht — nichts zu leeren.' );
            return;
        }

        WP_CLI::confirm( 'Alle Einträge aus dem Event-Log löschen?', $assoc_args );
        $deleted = $analytics->clear_events();
        WP_CLI::success( sprintf( '%d Einträge gelöscht.', $deleted ) );
    }

    /**
     * Deletes event-log rows older than the configured retention period.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha log prune
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function prune( $args, $assoc_args ): void {
        $analytics = creationell_captcha_analytics();
        if ( ! $analytics->table_exists() ) {
            WP_CLI::warning( 'Die Event-Log-Tabelle existiert nicht — nichts zu bereinigen.' );
            return;
        }

        $deleted = $analytics->prune_events();
        WP_CLI::success( sprintf( '%d abgelaufene Einträge entfernt.', $deleted ) );
    }
}
