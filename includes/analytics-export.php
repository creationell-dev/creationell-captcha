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
 * LibreOffice; the path column carries attacker-controlled request URIs. A
 * leading single quote forces the spreadsheet to treat the value as text.
 *
 * @param string $value Raw cell value.
 * @return string
 */
function creationell_captcha_csv_cell( string $value ): string {
    if ( '' !== $value && in_array( $value[0], [ '=', '+', '-', '@' ], true ) ) {
        return "'" . $value;
    }

    return $value;
}

/**
 * Streams the filtered event log as a CSV download.
 *
 * Hooked to admin-post.php. Requires the `manage_options` capability and a
 * valid nonce. The filter (search, event type, date range) is read from the
 * request via the shared parser, so the export mirrors the on-screen filter.
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

    $filter = creationell_captcha_events_query_args();
    $labels = creationell_captcha_analytics_labels();

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

    $analytics  = creationell_captcha_analytics();
    $batch_size = 1000;
    $offset     = 0;

    do {
        $rows = $analytics->query_events(
            $filter + [
                'limit'  => $batch_size,
                'offset' => $offset,
            ]
        );

        foreach ( $rows as $event ) {
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
        }

        $offset += $batch_size;
    } while ( count( $rows ) === $batch_size );

    if ( is_resource( $output ) ) {
        fclose( $output );
    }

    exit;
}
add_action( 'admin_post_creationell_captcha_export_events', 'creationell_captcha_export_events' );
