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
     * : How many rows to show. Default: 20. Gedeckelt auf 1000
     *   (Analytics::query_events()) — ein größerer Wert wird still auf 1000
     *   begrenzt, ohne Meldung.
     *
     * [--type=<type>]
     * : Filter by event type (verified, failed, firewall, ratelimit, underattack, underattack_passed, challenge).
     *
     * [--fields=<fields>]
     * : Komma-Liste der anzuzeigenden Spalten. Default: created_at,event_type,ip,path.
     *   Verfügbare Spalten: id, created_at, event_type, ip, user_id, user_agent,
     *   referrer, path, plugin, action, form_id, interceptor, reason,
     *   verification_data, request_body.
     *   Ein unbekannter Spaltenname ist ein Fehler (Exit 1) — auch dann, wenn die
     *   Abfrage keine Zeilen liefert (E3c: die Prüfung läuft gegen die feste
     *   Spaltenliste oben, nicht mehr nur gegen die gefundenen Zeilen).
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

        $requested_number = max( 1, (int) ( $assoc_args['number'] ?? 20 ) );
        $number           = min( 1000, $requested_number );
        $format           = $assoc_args['format'] ?? 'table';

        // B-M22: `Analytics::query_events()` deckelt `limit` intern auf 1000 —
        // bisher folgenlos für den Aufrufer: `--number=5000` lieferte still nur
        // 1000 Zeilen, ohne jede Meldung, dass etwas fehlt. Die Warnung nennt den
        // tatsächlich verwendeten Wert.
        if ( $requested_number > 1000 ) {
            WP_CLI::warning( sprintf( '--number=%d wird auf 1000 gedeckelt (Analytics::query_events()-Obergrenze).', $requested_number ) );
        }

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

        // CLI-7: `--fields` ging bisher unvalidiert an den Formatter. Weil
        // query_events() `SELECT *` macht, hat der Feldname keinen SQL-Kontakt
        // (kein SQLi) — eine unbekannte Spalte war schlicht eine leere Spalte
        // bei Exit 0. Anders als `--type`, das gegen die Ereignistypen geprüft
        // wird.
        //
        // E3c: die Whitelist stammte aus `array_keys($rows[0])` — bei einer leeren
        // Ergebnismenge (`empty($rows)` griff VOR dieser Prüfung) wurde sie nie
        // gebildet, `--fields=quatsch` auf einem leeren Log meldete „Keine
        // Ereignisse gefunden." und endete mit Exit 0, egal wie unsinnig der
        // Spaltenname war. Die Prüfung läuft jetzt gegen
        // `Analytics::event_columns()` (Strang N3 — die feste, gegen das
        // CREATE-TABLE-Schema getestete Spaltenliste) statt gegen die Zeilen —
        // sie arbeitet damit unabhängig davon, ob überhaupt Zeilen gefunden
        // wurden.
        $event_columns = \Creationell\Captcha\Analytics::event_columns();
        if ( isset( $assoc_args['fields'] ) ) {
            $resolved = self::resolve_fields( (string) $assoc_args['fields'], $event_columns );
            if ( ! empty( $resolved['unknown'] ) ) {
                WP_CLI::error(
                    sprintf(
                        'Unbekannte Spalte(n): %s. Verfügbar: %s.',
                        implode( ', ', $resolved['unknown'] ),
                        implode( ', ', $event_columns )
                    )
                );
            }
            if ( empty( $resolved['fields'] ) ) {
                WP_CLI::error( '--fields enthält keinen Spaltennamen.' );
            }
            $assoc_args['fields'] = implode( ',', $resolved['fields'] );
        }

        // B-M22: eine leere Ergebnismenge gab bisher IMMER den Menschentext aus,
        // auch bei --format=json/yaml/csv — ein Skript, das die Ausgabe parst,
        // bekam „Keine Ereignisse gefunden." statt eines gültigen leeren `[]`.
        if ( empty( $rows ) ) {
            if ( 'table' === $format ) {
                WP_CLI::log( 'Keine Ereignisse gefunden.' );
                return;
            }
            \WP_CLI\Utils\format_items(
                $format,
                [],
                isset( $assoc_args['fields'] ) ? explode( ',', $assoc_args['fields'] ) : [ 'created_at', 'event_type', 'ip', 'path' ]
            );
            return;
        }

        $default_fields = [ 'created_at', 'event_type', 'ip', 'path' ];

        $assoc_args['format'] = $format;
        $formatter            = new \WP_CLI\Formatter( $assoc_args, $default_fields );
        $formatter->display_items( array_map( [ self::class, 'escape_row' ], $rows ) );
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

        // CLI-5: wie in `log list` — der Rohwert aus der Tabelle geht nicht
        // unbearbeitet ins Terminal.
        $row    = self::escape_row( $rows[0] );
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
     * Runs every cell of an event row through escape_control_chars().
     *
     * @param array<string, mixed> $row One event-log row.
     * @return array<string, string>
     */
    public static function escape_row( array $row ): array {
        $clean = [];
        foreach ( $row as $field => $value ) {
            $clean[ (string) $field ] = self::escape_control_chars(
                is_scalar( $value ) || null === $value ? (string) $value : ''
            );
        }

        return $clean;
    }

    /**
     * Replaces terminal control characters with a printable escape.
     *
     * CLI-5: Die Spalten `user_agent`, `referrer`, `path`, `reason`,
     * `verification_data` und `request_body` stammen aus anonymen Requests.
     * `sanitize_text_field()` entfernt kein 0x1B, und `log list`/`log show`
     * gaben die Rohwerte über den Formatter aus — eine ESC-Sequenz aus einem
     * fremden User-Agent wirkte damit im Terminal des Administrators
     * (Farbwechsel, Cursorbewegung, Überschreiben früherer Zeilen). Neutralisiert
     * werden die C0-Steuerzeichen (0x00–0x1F, einschließlich ESC, CR und LF),
     * DEL (0x7F) und die UTF-8-kodierten C1-Steuerzeichen U+0080–U+009F (0xC2
     * gefolgt von 0x80–0x9F) — genau der Bereich, den ein Terminal auswertet.
     * Druckbare Zeichen und Mehrbyte-UTF-8 bleiben unverändert; die Ersetzung
     * arbeitet bewusst byteweise (kein `/u`), damit sie auch an einem ungültigen
     * UTF-8-Rest nicht abbricht.
     *
     * Kein Escaping heißt hier NICHT „unschädlich": ein Wert kann weiterhin
     * täuschende druckbare Zeichen enthalten (z. B. Unicode-Richtungswechsel).
     * Verhindert wird die Steuerung des Terminals, nicht die Täuschung des Lesers.
     *
     * @param string $value Raw column value.
     */
    public static function escape_control_chars( string $value ): string {
        $escaped = preg_replace_callback(
            '/[\x00-\x1F\x7F]|\xC2[\x80-\x9F]/',
            static function ( array $m ): string {
                if ( 1 === strlen( $m[0] ) ) {
                    return sprintf( '\\x%02X', ord( $m[0] ) );
                }

                return sprintf( '\\u{%04X}', ord( $m[0][1] ) );
            },
            $value
        );

        return is_string( $escaped ) ? $escaped : $value;
    }

    /**
     * Splits a `--fields` value and separates known from unknown columns.
     *
     * @param string             $requested Raw `--fields` value.
     * @param array<int, string> $available Column names of the result set.
     * @return array{fields: array<int, string>, unknown: array<int, string>}
     */
    public static function resolve_fields( string $requested, array $available ): array {
        $fields  = [];
        $unknown = [];

        foreach ( explode( ',', $requested ) as $raw ) {
            $field = trim( $raw );
            if ( '' === $field ) {
                continue;
            }
            if ( in_array( $field, $available, true ) ) {
                $fields[] = $field;
                continue;
            }
            $unknown[] = $field;
        }

        return [
            'fields'  => array_values( array_unique( $fields ) ),
            'unknown' => array_values( array_unique( $unknown ) ),
        ];
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
