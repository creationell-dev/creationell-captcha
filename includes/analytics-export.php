<?php
/**
 * CSV export of the analytics event log.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Neutralises a CSV cell against spreadsheet formula injection.
 *
 * A value beginning with =, +, - or @ can be executed as a formula by Excel or
 * LibreOffice; a leading single quote forces the spreadsheet to treat the value
 * as text. The `path`, `user_agent`, `referrer`, `verification_data` and
 * `request_body` columns all carry bytes an anonymous sender chose.
 *
 * B-M10: TAB and CR belong in the same list. Both are stripped as leading
 * whitespace while the cell is parsed, so `\treq(...)` and `\r=1+1` reach the
 * formula parser as if the control character were not there — the value is
 * then executed exactly like the four printable starters above. OWASP names
 * them alongside; they were the two the original list missed.
 *
 * NOT covered, deliberately: a value whose formula starter sits behind other
 * text, and a cell that is dangerous only inside a quoted field. The first is
 * not a formula for any spreadsheet, the second is handled by fputcsv()'s
 * quoting. What this function promises is exactly "the first character cannot
 * start a formula".
 *
 * @param string $value Raw cell value.
 * @return string
 */
function creationell_captcha_csv_cell( string $value ): string {
    if ( '' !== $value && in_array( $value[0], [ '=', '+', '-', '@', "\t", "\r" ], true ) ) {
        return "'" . $value;
    }

    return $value;
}

/**
 * The default upper bound on rows in a single CSV export.
 */
const CREATIONELL_CAPTCHA_EXPORT_MAX_ROWS = 50000;

/**
 * Streams the filtered event log as a CSV download.
 *
 * Hooked to admin-post.php. Requires the `manage_options` capability and a
 * valid nonce. The filter (search, event type, date range) is read from the
 * request via the shared parser, so the export mirrors the on-screen filter.
 *
 * Every reason to refuse is checked BEFORE the first byte goes out. Once the
 * Content-Disposition header and the BOM are on the wire the response is
 * committed to being a successful download, and anything that goes wrong
 * afterwards reaches the admin as a file that looks complete (AF-10/DS-9).
 */
function creationell_captcha_export_events(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die(
            esc_html__( 'Keine Berechtigung für diesen Export.', 'creationell-captcha' ),
            '',
            [ 'response' => 403 ]
        );
    }

    check_admin_referer( 'creationell_captcha_export_events' );

    $settings  = creationell_captcha_get_settings();
    $analytics = creationell_captcha_analytics();
    $filter    = creationell_captcha_events_query_args();
    $labels    = creationell_captcha_analytics_labels();

    // B-M3: there used to be a third guard here, refusing the export outright
    // whenever `analytics_event_log` was off. The stated goal of AF-10 was to
    // prevent a header-only CSV, and the two guards below deliver exactly that
    // — a missing table and an empty result set are the only two ways to get
    // one. Refusing on the SETTING went further and made already-collected
    // rows unreachable through the web UI: switching the log off for privacy
    // reasons is precisely the moment an operator wants to save what is
    // already there, and the scheduled retention sweep (DS-1) keeps deleting
    // it meanwhile. `wp creacaptcha log list --format=csv` still worked, which
    // is not a replacement for the button in the backend.

    // AF-10, guard 1: without the table the SELECT fails inside $wpdb. With
    // WP_DEBUG_DISPLAY on, the MySQL error is printed — into the middle of a
    // response already declared as text/csv.
    if ( ! $analytics->table_exists() ) {
        wp_die(
            esc_html__( 'Die Event-Log-Tabelle fehlt. Bitte die Einstellungen einmal speichern oder „wp creacaptcha repair" ausführen.', 'creationell-captcha' ),
            esc_html__( 'Export nicht möglich', 'creationell-captcha' ),
            [
                'response'  => 409,
                'back_link' => true,
            ]
        );
    }

    /*
     * W3-1: anchor the snapshot BEFORE counting.
     *
     * `$total` used to be counted against a live table and the batch walk then
     * started at `before_id = 0`, i.e. at whatever the newest row was by the
     * time the first batch ran. Failure case, no error and no sign of it in
     * the file: `$total == $max_rows`, and five rows arrive between the count
     * and the first batch. The walk starts at the newest of those five, and
     * after `$max_rows` written rows the budget is spent — the five OLDEST
     * rows of the set the operator asked for are missing from a file that
     * looks complete. That is the same class DS-9 set out to remove.
     *
     * The anchor is the id of the newest matching row at this instant. Both
     * the count and the walk are restricted to `id <= anchor`, so they talk
     * about the same set; rows written afterwards get higher ids and stay
     * outside this export entirely — which is what a snapshot means.
     */
    $newest = $analytics->query_events( $filter + [ 'limit' => 1 ] );
    $anchor = isset( $newest[0]['id'] ) ? (int) $newest[0]['id'] : 0;

    // `before_id` is exclusive, so the anchor row itself needs anchor + 1. With
    // no rows at all this yields `id < 1`, i.e. the empty set — guard 2 below
    // then refuses, exactly as it did before.
    $anchored = $filter;
    $anchored['before_id'] = $anchor + 1;

    $total = $analytics->count_events( $anchored );

    if ( 0 === $total ) {
        wp_die(
            esc_html__( 'Für den aktuellen Filter gibt es keine Ereignisse zu exportieren.', 'creationell-captcha' ),
            esc_html__( 'Export nicht möglich', 'creationell-captcha' ),
            [
                'response'  => 409,
                'back_link' => true,
            ]
        );
    }

    /**
     * Filters the maximum number of event-log rows a single CSV export may
     * contain.
     *
     * The export streams its response, so the HTTP 200 and the
     * Content-Disposition header are already sent when a long-running export
     * hits the PHP time or memory limit; the browser then stores a truncated
     * file that carries no sign of being incomplete (DS-9). Rather than
     * risking that, the export refuses up front when the filtered result set
     * is larger than this bound and asks for a narrower date range.
     *
     * Raise the value only for environments that can stream that many rows
     * within their limits.
     *
     * @since 1.1.0
     *
     * @param int                                                                          $max_rows Maximum rows per export. Default 50000.
     * @param array{search: string, event_type: string, date_from: string, date_to: string} $filter   The active event-log filter.
     */
    $max_rows = (int) apply_filters(
        'creationell_captcha_export_max_rows',
        CREATIONELL_CAPTCHA_EXPORT_MAX_ROWS,
        $filter
    );
    $max_rows = max( 1, $max_rows );

    if ( $total > $max_rows ) {
        wp_die(
            esc_html(
                sprintf(
                    /* translators: 1: number of matching rows, 2: maximum rows per export. */
                    __( 'Der Filter trifft %1$s Ereignisse, exportiert werden höchstens %2$s. Bitte den Zeitraum eingrenzen — ein größerer Export würde mitten im Download abbrechen und eine unvollständige Datei hinterlassen, die vollständig aussieht.', 'creationell-captcha' ),
                    number_format_i18n( $total ),
                    number_format_i18n( $max_rows )
                )
            ),
            esc_html__( 'Export zu groß', 'creationell-captcha' ),
            [
                'response'  => 409,
                'back_link' => true,
            ]
        );
    }

    nocache_headers();
    header( 'Content-Type: text/csv; charset=utf-8' );
    header(
        'Content-Disposition: attachment; filename="creationell-captcha-events-'
        . gmdate( 'Y-m-d' ) . '.csv"'
    );

    $output = fopen( 'php://output', 'w' );

    // UTF-8 BOM so spreadsheet apps detect the encoding (umlauts).
    echo "\xEF\xBB\xBF";

    fputcsv(
        $output,
        [
            __( 'Zeitpunkt (UTC)', 'creationell-captcha' ),
            __( 'Ereignis', 'creationell-captcha' ),
            __( 'Plugin', 'creationell-captcha' ),
            __( 'Aktion', 'creationell-captcha' ),
            __( 'Formular-ID', 'creationell-captcha' ),
            __( 'Interceptor', 'creationell-captcha' ),
            __( 'Grund', 'creationell-captcha' ),
            __( 'IP-Adresse', 'creationell-captcha' ),
            __( 'Benutzer-ID', 'creationell-captcha' ),
            __( 'Pfad', 'creationell-captcha' ),
            __( 'Referrer', 'creationell-captcha' ),
            __( 'User-Agent', 'creationell-captcha' ),
            __( 'Verifizierungsdaten', 'creationell-captcha' ),
            __( 'Request-Body', 'creationell-captcha' ),
        ],
        ',',
        '"',
        ''
    );

    // DS-9: the batch walk used LIMIT/OFFSET over `ORDER BY id DESC`. The
    // event log grows at the head, so every row inserted while the export was
    // running pushed the window down and the previous batch's tail came back a
    // second time — the same rows twice in one file. `before_id` anchors each
    // batch below the smallest id already written; since ids only grow, the
    // walk covers each row of the starting set exactly once, and rows written
    // during the export simply stay outside this snapshot.
    $batch_size = 1000;
    $before_id  = $anchor + 1;
    $written    = 0;

    do {
        $args              = $filter + [ 'limit' => $batch_size ];
        $args['before_id'] = $before_id;

        $rows      = $analytics->query_events( $args );
        $cursor_at = $before_id;

        foreach ( $rows as $event ) {
            $row_id = (int) ( $event['id'] ?? 0 );
            if ( $row_id > 0 ) {
                $before_id = $row_id;
            }
            $event_type = (string) ( $event['event_type'] ?? '' );
            $interceptor = empty( $event['interceptor'] )
                ? __( 'nein', 'creationell-captcha' )
                : __( 'ja', 'creationell-captcha' );
            fputcsv(
                $output,
                [
                    creationell_captcha_csv_cell( (string) ( $event['created_at'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $labels[ $event_type ] ?? $event_type ) ),
                    creationell_captcha_csv_cell( (string) ( $event['plugin'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['action'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['form_id'] ?? '' ) ),
                    creationell_captcha_csv_cell( $interceptor ),
                    creationell_captcha_csv_cell( (string) ( $event['reason'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['ip'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['user_id'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['path'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['referrer'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['user_agent'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['verification_data'] ?? '' ) ),
                    creationell_captcha_csv_cell( (string) ( $event['request_body'] ?? '' ) ),
                ],
                ',',
                '"',
                ''
            );

            ++$written;
        }

        // Termination is not left to the data: the loop stops at the row
        // budget checked above, and also when a batch failed to move the
        // cursor (rows without a usable id would otherwise re-query forever).
    } while ( count( $rows ) === $batch_size && $written < $max_rows && $before_id !== $cursor_at );

    if ( is_resource( $output ) ) {
        fclose( $output );
    }

    exit;
}
add_action( 'admin_post_creationell_captcha_export_events', 'creationell_captcha_export_events' );
