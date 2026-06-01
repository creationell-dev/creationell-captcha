<?php
/**
 * Analytics recorder — aggregate counters and optional event log.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Records security events into per-day and per-hour aggregate counters and,
 * when the detailed event log is enabled, into a dedicated database table.
 * See the module-6 and the analytics-dashboard design specs.
 */
class Analytics {

    /**
     * The option holding the aggregate daily counters.
     */
    private const OPTION = 'creationell_captcha_analytics';

    /**
     * The option holding the aggregate hourly counters (24-hour view).
     */
    private const OPTION_HOURLY = 'creationell_captcha_analytics_hourly';

    /**
     * The seven recognised event types.
     */
    private const TYPES = [ 'verified', 'failed', 'firewall', 'ratelimit', 'underattack', 'underattack_passed', 'challenge' ];

    /**
     * Aggregate daily-counter retention, in days.
     */
    private const COUNTER_RETENTION_DAYS = 90;

    /**
     * Aggregate hourly-counter retention, in hours.
     */
    private const HOURLY_RETENTION_HOURS = 48;

    /**
     * Pending daily counter deltas: { bucket => { type => count } }. Flushed
     * on `shutdown` so a request that triggers N events incurs at most one
     * get_option/update_option round-trip per counter table, regardless of N.
     *
     * @var array<string, array<string, int>>
     */
    private static array $daily_deltas = [];

    /**
     * Pending hourly counter deltas: { bucket => { type => count } }.
     *
     * @var array<string, array<string, int>>
     */
    private static array $hourly_deltas = [];

    /**
     * Whether the shutdown flush has already been hooked for this request.
     */
    private static bool $flush_hooked = false;

    /**
     * Records one security event: bumps the daily and hourly counters and —
     * when the detailed event log is enabled and the per-type toggle is on —
     * writes a table row. Never fatals.
     *
     * @param string               $type    One of the recognised event types.
     * @param array<string, mixed> $context Optional caller-supplied context.
     */
    public function record( string $type, array $context = [] ): void {
        if ( creationell_captcha_is_disabled() ) {
            return;
        }
        if ( ! in_array( $type, self::TYPES, true ) ) {
            return;
        }

        // Aggregate counters always run — they are PII-free and the dashboard
        // relies on them to show "Challenges ausgestellt" / etc. lines.
        $this->bump_counter( $type );
        $this->bump_hourly_counter( $type );

        $settings = creationell_captcha_get_settings();
        if ( empty( $settings['analytics_event_log'] ) ) {
            return;
        }

        // Per-event-type toggle — opt-out for noisy types.
        if ( empty( $settings[ 'log_' . $type ] ) ) {
            return;
        }

        $this->log_row( $type, $context );
    }

    /**
     * Accumulates today's counter delta in the request-local cache.
     */
    private function bump_counter( string $type ): void {
        $today = gmdate( 'Y-m-d' );
        self::$daily_deltas[ $today ][ $type ] = ( self::$daily_deltas[ $today ][ $type ] ?? 0 ) + 1;
        $this->ensure_flush_hook();
    }

    /**
     * Accumulates the current hour's counter delta in the request-local cache.
     */
    private function bump_hourly_counter( string $type ): void {
        $hour = gmdate( 'Y-m-d H' );
        self::$hourly_deltas[ $hour ][ $type ] = ( self::$hourly_deltas[ $hour ][ $type ] ?? 0 ) + 1;
        $this->ensure_flush_hook();
    }

    /**
     * Idempotently registers the shutdown flush. Called the first time a delta
     * is recorded in this request.
     */
    private function ensure_flush_hook(): void {
        if ( self::$flush_hooked ) {
            return;
        }
        self::$flush_hooked = true;
        add_action( 'shutdown', [ self::class, 'flush_pending_deltas' ] );
    }

    /**
     * Flushes the accumulated daily and hourly counter deltas back to the
     * options table. Reads the current value first and adds the deltas, so
     * concurrent updates from parallel requests are not lost (the underlying
     * get+update is still non-atomic, but only one round-trip per request
     * narrows the race window considerably compared to one round-trip per
     * event).
     */
    public static function flush_pending_deltas(): void {
        if ( ! empty( self::$daily_deltas ) ) {
            self::apply_deltas(
                self::OPTION,
                self::$daily_deltas,
                self::COUNTER_RETENTION_DAYS,
                'Y-m-d',
                86400
            );
            self::$daily_deltas = [];
        }
        if ( ! empty( self::$hourly_deltas ) ) {
            self::apply_deltas(
                self::OPTION_HOURLY,
                self::$hourly_deltas,
                self::HOURLY_RETENTION_HOURS,
                'Y-m-d H',
                3600
            );
            self::$hourly_deltas = [];
        }
    }

    /**
     * Merges the given { bucket => { type => count } } deltas into the option
     * value and prunes buckets older than the retention window.
     *
     * @param string                                    $option         Option name to read+write.
     * @param array<string, array<string, int>>         $deltas         Pending increments by bucket and type.
     * @param int                                       $retention      Retention amount (days or hours).
     * @param string                                    $bucket_format  gmdate() format for bucket keys.
     * @param int                                       $bucket_seconds Seconds per retention unit (86400 or 3600).
     */
    private static function apply_deltas( string $option, array $deltas, int $retention, string $bucket_format, int $bucket_seconds ): void {
        $data = get_option( $option, [] );
        if ( ! is_array( $data ) ) {
            $data = [];
        }

        foreach ( $deltas as $bucket => $type_increments ) {
            if ( ! isset( $data[ $bucket ] ) || ! is_array( $data[ $bucket ] ) ) {
                $data[ $bucket ] = [];
            }
            foreach ( $type_increments as $type => $count ) {
                $current                  = isset( $data[ $bucket ][ $type ] ) ? (int) $data[ $bucket ][ $type ] : 0;
                $data[ $bucket ][ $type ] = $current + (int) $count;
            }
        }

        // Drop buckets older than the retention window. The 'Y-m-d' and
        // 'Y-m-d H' formats both sort lexically as chronologically.
        $cutoff = gmdate( $bucket_format, time() - $retention * $bucket_seconds );
        foreach ( array_keys( $data ) as $key ) {
            if ( (string) $key < $cutoff ) {
                unset( $data[ $key ] );
            }
        }

        update_option( $option, $data, false );
    }

    /**
     * Writes one row into the event-log table and occasionally prunes it.
     * Honours the optional IP-anonymisation and request-body-fingerprint
     * toggles from Modul 11c.
     *
     * @param string               $type    The event type.
     * @param array<string, mixed> $context Caller-supplied context.
     */
    private function log_row( string $type, array $context = [] ): void {
        global $wpdb;
        $table    = $this->table_name();
        $settings = creationell_captcha_get_settings();

        $ip = creationell_captcha_get_client_ip();
        if ( ! empty( $settings['analytics_anonymize_ip'] ) ) {
            $ip = creationell_captcha_anonymize_ip( $ip );
        }

        $body = ! empty( $settings['log_body'] )
            ? creationell_captcha_request_body_fingerprint()
            : '';

        $wpdb->insert(
            $table,
            [
                'created_at'        => gmdate( 'Y-m-d H:i:s' ),
                'event_type'        => $type,
                'ip'                => $ip,
                'path'              => $this->current_path(),
                'user_id'           => get_current_user_id(),
                'user_agent'        => $this->server_value( 'HTTP_USER_AGENT', 255 ),
                'referrer'          => $this->server_value( 'HTTP_REFERER', 255 ),
                'verification_data' => $this->verification_data(),
                'plugin'            => substr( sanitize_text_field( (string) ( $context['plugin'] ?? '' ) ), 0, 32 ),
                'action'            => substr( sanitize_key( (string) ( $context['action'] ?? '' ) ), 0, 32 ),
                'form_id'           => substr( sanitize_text_field( (string) ( $context['form_id'] ?? '' ) ), 0, 32 ),
                'interceptor'       => empty( $context['interceptor'] ) ? 0 : 1,
                'reason'            => substr( sanitize_text_field( (string) ( $context['reason'] ?? '' ) ), 0, 255 ),
                'request_body'      => $body,
            ],
            [ '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' ]
        );

        // Prune roughly every twentieth write to bound the table without a
        // DELETE on every insert.
        if ( 1 === random_int( 1, 20 ) ) {
            $this->prune_events();
        }
    }

    /**
     * Reads a $_SERVER header value, sanitised and length-capped.
     *
     * @param string $key The $_SERVER key.
     * @param int    $max Maximum length.
     */
    private function server_value( string $key, int $max ): string {
        $raw = isset( $_SERVER[ $key ] ) ? (string) wp_unslash( $_SERVER[ $key ] ) : '';

        return substr( sanitize_text_field( $raw ), 0, $max );
    }

    /**
     * The submitted ALTCHA solution payload for the current request, capped.
     */
    private function verification_data(): string {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the payload is the token; read-only diagnostic copy.
        $raw = isset( $_POST['altcha'] ) ? (string) wp_unslash( $_POST['altcha'] ) : '';

        return substr( sanitize_text_field( $raw ), 0, 2048 );
    }

    /**
     * Deletes event-log rows older than the configured retention period.
     *
     * @return int Number of rows deleted.
     */
    public function prune_events(): int {
        global $wpdb;
        $settings = creationell_captcha_get_settings();
        $days     = max( 1, min( 365, (int) ( $settings['analytics_log_retention'] ?? 30 ) ) );
        $cutoff   = gmdate( 'Y-m-d H:i:s', time() - $days * 86400 );
        $table    = $this->table_name();

        return (int) $wpdb->query(
            $wpdb->prepare( "DELETE FROM `{$table}` WHERE created_at < %s", $cutoff )
        );
    }

    /**
     * Whether the event-log table currently exists.
     */
    public function table_exists(): bool {
        global $wpdb;
        $table = $this->table_name();

        return $wpdb->get_var(
            $wpdb->prepare( 'SHOW TABLES LIKE %s', $table )
        ) === $table;
    }

    /**
     * Deletes every row from the event-log table.
     *
     * @return int Number of rows deleted.
     */
    public function clear_events(): int {
        global $wpdb;
        $table = $this->table_name();

        return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $table ) );
    }

    /**
     * The current request path for the event log.
     *
     * Returns only the URI path component — the query string is dropped so
     * tokens passed as GET parameters (magic-login links, API keys, …) do
     * not leak into the persistent event log. Strips control characters
     * (DB hygiene) and caps at 255 bytes. The dashboard escapes the value
     * on output.
     */
    private function current_path(): string {
        $raw = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
        if ( '' === $raw ) {
            return '';
        }

        $path = wp_parse_url( $raw, PHP_URL_PATH );
        if ( ! is_string( $path ) || '' === $path ) {
            return '';
        }

        $path = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $path );

        return substr( $path, 0, 255 );
    }

    /**
     * The fully-qualified event-log table name.
     */
    private function table_name(): string {
        global $wpdb;

        return $wpdb->prefix . 'creationell_captcha_events';
    }

    /**
     * Creates or updates the event-log table. Idempotent — safe to call
     * repeatedly.
     */
    public function ensure_table(): void {
        global $wpdb;
        $table   = $this->table_name();
        $collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created_at datetime NOT NULL,
  event_type varchar(20) NOT NULL,
  ip varchar(45) NOT NULL DEFAULT '',
  path varchar(255) NOT NULL DEFAULT '',
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  user_agent varchar(255) NOT NULL DEFAULT '',
  referrer varchar(255) NOT NULL DEFAULT '',
  plugin varchar(32) NOT NULL DEFAULT '',
  action varchar(32) NOT NULL DEFAULT '',
  form_id varchar(32) NOT NULL DEFAULT '',
  interceptor tinyint(1) NOT NULL DEFAULT 0,
  reason varchar(255) NOT NULL DEFAULT '',
  verification_data varchar(2048) NOT NULL DEFAULT '',
  request_body varchar(2048) NOT NULL DEFAULT '',
  PRIMARY KEY  (id),
  KEY created_at (created_at),
  KEY event_type_created (event_type, created_at)
) {$collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );

        // dbDelta is unreliable for index additions on existing tables — make
        // sure the composite index is in place even when dbDelta skipped it.
        $this->ensure_event_type_index();
    }

    /**
     * Idempotently adds the composite (event_type, created_at) index to the
     * events table. Dashboard queries that filter by event_type benefit from
     * a covering composite, whereas the standalone created_at index alone
     * forces a filesort over a typed slice.
     */
    private function ensure_event_type_index(): void {
        global $wpdb;
        $table = $this->table_name();

        $existing = $wpdb->get_results(
            $wpdb->prepare(
                'SHOW INDEX FROM %i WHERE Key_name = %s',
                $table,
                'event_type_created'
            )
        );

        if ( ! empty( $existing ) ) {
            return;
        }

        $wpdb->query(
            $wpdb->prepare(
                'ALTER TABLE %i ADD KEY event_type_created (event_type, created_at)',
                $table
            )
        );
    }

    /**
     * Returns the aggregate daily counters, keyed by date.
     *
     * @return array<string, array<string, int>>
     */
    public function get_daily_counts(): array {
        $data = get_option( self::OPTION, [] );

        return is_array( $data ) ? $data : [];
    }

    /**
     * Returns the aggregate hourly counters, keyed by 'Y-m-d H' (UTC).
     *
     * @return array<string, array<string, int>>
     */
    public function get_hourly_counts(): array {
        $data = get_option( self::OPTION_HOURLY, [] );

        return is_array( $data ) ? $data : [];
    }

    /**
     * Builds the WHERE clause and bound parameters for an event-log filter.
     *
     * @param array<string, mixed> $args Filter args: id, search, event_type, date_from, date_to.
     * @return array{0: string, 1: array<int, string>} SQL fragment ('' or ' WHERE …') and params.
     */
    private function build_event_filter( array $args ): array {
        global $wpdb;

        $where  = [];
        $params = [];

        $event_type = isset( $args['event_type'] ) ? (string) $args['event_type'] : '';
        if ( in_array( $event_type, self::TYPES, true ) ) {
            $where[]  = 'event_type = %s';
            $params[] = $event_type;
        }

        $id = isset( $args['id'] ) ? (int) $args['id'] : 0;
        if ( $id > 0 ) {
            $where[]  = 'id = %d';
            $params[] = $id;
        }

        $search = isset( $args['search'] ) ? trim( (string) $args['search'] ) : '';
        if ( '' !== $search ) {
            $like     = '%' . $wpdb->esc_like( $search ) . '%';
            $where[]  = '( ip LIKE %s OR path LIKE %s )';
            $params[] = $like;
            $params[] = $like;
        }

        $date_from = isset( $args['date_from'] ) ? (string) $args['date_from'] : '';
        if ( '' !== $date_from ) {
            $where[]  = 'created_at >= %s';
            $params[] = $date_from . ' 00:00:00';
        }

        $date_to = isset( $args['date_to'] ) ? (string) $args['date_to'] : '';
        if ( '' !== $date_to ) {
            $where[]  = 'created_at <= %s';
            $params[] = $date_to . ' 23:59:59';
        }

        $clause = empty( $where ) ? '' : ' WHERE ' . implode( ' AND ', $where );

        return [ $clause, $params ];
    }

    /**
     * Returns event-log rows matching the given filter, newest first.
     *
     * @param array<string, mixed> $args Filter args (id, search, event_type,
     *                                   date_from, date_to) plus `limit` (1–1000)
     *                                   and `offset` (>= 0).
     * @return array<int, array<string, string>>
     */
    public function query_events( array $args ): array {
        global $wpdb;
        $table = $this->table_name();

        [ $clause, $params ] = $this->build_event_filter( $args );

        $limit  = max( 1, min( 1000, (int) ( $args['limit'] ?? 50 ) ) );
        $offset = max( 0, (int) ( $args['offset'] ?? 0 ) );

        $sql      = "SELECT * FROM `{$table}`{$clause} ORDER BY id DESC LIMIT %d OFFSET %d";
        $params[] = $limit;
        $params[] = $offset;

        $rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );

        return is_array( $rows ) ? $rows : [];
    }

    /**
     * Counts the event-log rows matching the given filter.
     *
     * @param array<string, mixed> $args Filter args (id, search, event_type, date_from, date_to).
     * @return int
     */
    public function count_events( array $args ): int {
        global $wpdb;
        $table = $this->table_name();

        [ $clause, $params ] = $this->build_event_filter( $args );

        $sql = "SELECT COUNT(*) FROM `{$table}`{$clause}";

        if ( empty( $params ) ) {
            return (int) $wpdb->get_var( $sql );
        }

        return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
    }
}
