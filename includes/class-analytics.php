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
     * The event types whose request actually carries an ALTCHA payload, i.e.
     * the only ones for which the `verification_data` column has diagnostic
     * value. See verification_data() for why the other types must not copy it.
     */
    private const VERIFICATION_DATA_TYPES = [ 'verified', 'failed', 'underattack_passed' ];

    /**
     * Cron hook that enforces the configured event-log retention.
     */
    public const PRUNE_HOOK = 'creationell_captcha_prune_events';

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
     * Request-local memo for table_exists().
     *
     * DS-4 put a table_exists() guard in front of every log_row() insert; that
     * guard sits on the hot path of a logging-enabled site, so the `SHOW
     * TABLES` behind it must not run once per event. `null` means "not yet
     * checked in this request"; ensure_table() resets it to null so a table
     * created mid-request is picked up.
     */
    private static ?bool $table_exists_memo = null;

    /**
     * The blog the memo above was taken on, or -1 when it holds nothing.
     *
     * B-M11: table_name() reads `$wpdb->prefix`, and `switch_to_blog()` rewires
     * that — the memo did not follow, so an answer taken on site A would have
     * been reused for site B's differently named table. Nothing in the loaded
     * plugin switches sites today (uninstall.php does, but never loads this
     * class), so this is a latent trap rather than a live bug; the network
     * deactivation loop added in this release walks sites with the plugin
     * loaded, which is exactly the neighbourhood where it would go off.
     */
    private static int $table_exists_memo_blog = -1;

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
     * options table.
     *
     * DS-8 — known and accepted limitation, stated here so no caller assumes
     * more than the code delivers: the read-modify-write below is NOT atomic.
     * Two requests that flush at the same time can both read the same value
     * and the later write wins, so the counters can under-count. Batching the
     * whole request into a single round-trip per counter table narrows the
     * window compared to one round-trip per event — it does not close it.
     *
     * The consequence is confined to the dashboard's aggregate tiles: the
     * counters are display-only statistics, no protection decision reads them,
     * and the detailed event log (when enabled) is written per row and is
     * unaffected. A lock or a per-row counter table would be the fix if these
     * numbers ever had to be exact.
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
     * DS-7 — scope of `analytics_anonymize_ip`, spelled out so the field list
     * below is not mistaken for an anonymised record: the toggle truncates the
     * `ip` column and nothing else. `user_agent`, `referrer`, `user_id`,
     * `verification_data` and `request_body` are stored as submitted, and
     * `path` keeps the request path (only its query string is dropped, see
     * current_path()) — a row can therefore still be attributable with the
     * toggle on. The event log as a whole is opt-in and bounded by
     * `analytics_log_retention`.
     *
     * @param string               $type    The event type.
     * @param array<string, mixed> $context Caller-supplied context.
     */
    private function log_row( string $type, array $context = [] ): void {
        global $wpdb;
        $table    = $this->table_name();
        $settings = creationell_captcha_get_settings();

        // DS-4: the table is created by ensure_table(), which runs on the
        // settings WRITE hook (creationell_captcha_sync_event_log_table(), see
        // includes/settings.php), on `wp creacaptcha repair` and on import —
        // no longer inside the sanitize callback, which E3b turned back into a
        // side-effect-free function. A write path that turns
        // `analytics_event_log` on without any of those leaves the flag on and
        // the table absent — every event then became a silent failed INSERT
        // plus a MySQL error in the log. Skip the write instead; creating a
        // table here would mean DDL on an anonymous request path.
        if ( ! $this->table_exists() ) {
            // The advice names `repair` first on purpose: since E3b the hook
            // fires on an actual OPTION CHANGE. Saving the settings screen
            // without changing anything writes nothing, fires neither
            // update_option_ nor add_option_ — and creates no table.
            creationell_captcha_log(
                'Event-Log ist aktiv, aber die Tabelle fehlt — Ereignis nicht gespeichert. '
                . '"wp creacaptcha repair" ausführen oder die Einstellungen mit einer Änderung speichern.'
            );
            return;
        }

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
                'verification_data' => $this->verification_data( $type ),
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
        // DELETE on every insert. Kept alongside the scheduled sweep from
        // DS-1: with DISABLE_WP_CRON and no system cron the daily event never
        // fires, and this opportunistic path is then the only one left.
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
     *
     * DS-6: `$_POST['altcha']` is anonymous, attacker-chosen input, and up to
     * 2048 bytes of it used to be copied into EVERY logged row — including
     * `firewall`, `ratelimit`, `underattack` and `challenge` events. None of
     * those four ever verified the value: the request was blocked, throttled
     * or served an interstitial, or it merely fetched a new challenge. The
     * copied bytes were therefore unverified input with no relation to the
     * event, on exactly the high-volume anonymous paths — roughly 2 KB of log
     * growth per blocked request, chosen by the sender. The column is now
     * filled only for the event types that really are a verification attempt.
     *
     * What this does NOT do: it does not bound the field for those remaining
     * types — a `failed` event still stores up to 2048 attacker-chosen bytes.
     * The bound there is the retention window (now scheduler-enforced, DS-1)
     * plus the fact that the whole event log is opt-in.
     *
     * @param string $type The event type being logged.
     */
    private function verification_data( string $type ): string {
        if ( ! in_array( $type, self::VERIFICATION_DATA_TYPES, true ) ) {
            return '';
        }

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
     * Makes sure the retention sweep is on the cron schedule. Idempotent —
     * registered on `init`, so a slot lost to a `wp cron event delete`, a
     * partial DB restore or a plugin re-activation comes back by itself.
     *
     * DS-1: before this, `analytics_log_retention` was enforced only by the
     * 1-in-20 opportunistic prune inside log_row() and by the CLI. Both need
     * ongoing writes — switch the event log off (or lose the traffic) and the
     * existing rows, IP/user-agent/referrer included, stayed forever even
     * though the setting promised a retention window. The sweep below runs on
     * its own schedule and deliberately does NOT look at `analytics_event_log`:
     * a switched-off log is precisely the case that needs it.
     *
     * W3-2 — it DOES look at the kill switch, and both halves do. Deleting rows
     * is the only destructive background operation this plugin has, and an
     * operator who sets `CREATIONELL_CAPTCHA_DISABLE` during an incident is
     * usually doing it to freeze the state, not to keep a sweep running against
     * the evidence he is about to read. "Off" has to mean "deletes nothing
     * either"; record() has read the same switch since Modul 11c.
     *
     * The slot itself is left alone rather than unscheduled: the switch is a
     * wp-config constant and can come back at any request, and clearing the
     * schedule here would make the kill switch quietly rewrite cron state.
     *
     * N6 — the limit of that argument, stated openly because the setting does
     * not state it: it holds for the SHORT use (freeze the state during an
     * incident). A kill switch that stays set longer than the retention window
     * — a staging wp-config copied to production, "plugin functionally off"
     * instead of deactivation — means the window never elapses, and the rows
     * DS-1 was built for (IP, user agent, referrer, user ID of a log that is
     * already switched off) stay forever. The guard is kept; the state is no
     * longer silent: `wp creacaptcha doctor` reports it (check 22,
     * `Doctor_Command::retention_sweep_check()`), the help text of
     * `analytics_log_retention` names it, and `wp creacaptcha log prune` runs
     * regardless of the kill switch as the way out.
     */
    public static function ensure_prune_schedule(): void {
        if ( creationell_captcha_is_disabled() ) {
            return;
        }

        if ( false !== wp_next_scheduled( self::PRUNE_HOOK ) ) {
            return;
        }

        wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::PRUNE_HOOK );
    }

    /**
     * Cron callback for self::PRUNE_HOOK — deletes rows past the retention
     * window. Skips silently when the kill switch is set (W3-2, see
     * ensure_prune_schedule()) or when the table does not exist.
     */
    public static function run_scheduled_prune(): void {
        if ( creationell_captcha_is_disabled() ) {
            return;
        }

        $analytics = new self();

        if ( ! $analytics->table_exists() ) {
            return;
        }

        $analytics->prune_events();
    }

    /**
     * Whether the event-log table currently exists.
     *
     * DS-5: the table name goes through esc_like() before it is bound as a
     * LIKE pattern. Without it the underscores in `<prefix>creationell_captcha_events`
     * stay single-character wildcards, so any table matching that shape — say
     * `wp0creationell0captcha0events` — can be returned by `SHOW TABLES` and
     * compared unequal to the real name, making this method answer `false`
     * while the table is right there. `prepare()` escapes the value for the
     * SQL string literal, it does not neutralise LIKE metacharacters.
     */
    public function table_exists(): bool {
        $blog = self::current_blog_id();

        if ( null !== self::$table_exists_memo && $blog === self::$table_exists_memo_blog ) {
            return self::$table_exists_memo;
        }

        global $wpdb;
        $table = $this->table_name();
        $like  = $wpdb->esc_like( $table );

        self::$table_exists_memo      = $wpdb->get_var(
            $wpdb->prepare( 'SHOW TABLES LIKE %s', $like )
        ) === $table;
        self::$table_exists_memo_blog = $blog;

        return self::$table_exists_memo;
    }

    /**
     * The current blog id, or 0 on a single site (B-M11).
     *
     * `get_current_blog_id()` is a WordPress core function and always exists at
     * runtime; the guard is here because the Ebene-2 suites load this class
     * without the WordPress bootstrap and must not have to stub a function to
     * keep a memo key correct.
     */
    private static function current_blog_id(): int {
        return function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 0;
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
     *
     * The path itself comes from creationell_captcha_request_path(), the same
     * root the interceptor, the inject pass, the rate limiter, the firewall and
     * the REST detection use (audit module 27, finding C1). It used to run
     * `wp_parse_url( REQUEST_URI, PHP_URL_PATH )` here, which reads a request
     * target as if it were a URL: for `//kontakt/` the first segment becomes
     * the HOST and the path collapses to `/`, for `///kontakt/` to `''`.
     *
     * That mattered more here than anywhere else. The one-character spelling
     * `POST //kontakt` was the bypass the C1 fix closed — and the event log is
     * the record an operator reads afterwards to find out whether somebody
     * tried it. With the old parser the attempt was logged under `/`, i.e.
     * under a path that was never requested, so the forensic trail pointed
     * away from the attack instead of at it.
     *
     * Deliberately kept: the empty answer when the request carries no
     * REQUEST_URI at all (WP-Cron, WP-CLI, unit runs). The root would report
     * `/` there, which reads like a real front-page request; `''` says "no
     * request path", which is what actually happened.
     */
    private function current_path(): string {
        $raw = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
        if ( '' === $raw ) {
            return '';
        }

        $path = creationell_captcha_request_path();

        $path = (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $path );

        return substr( $path, 0, 255 );
    }

    /**
     * The columns of the event-log table, in schema order.
     *
     * E3c — why this exists as a method rather than being derived from a row:
     * `wp creacaptcha log list --fields=quatsch` used to build its whitelist
     * from `array_keys( $rows[0] )`, so on an EMPTY log the command returned
     * "Keine Ereignisse gefunden." and exit 0 without ever looking at the
     * `--fields` value. A typo was reported as a typo on a busy site and
     * silently accepted on a quiet one. A single source of truth that does not
     * depend on there being data closes that.
     *
     * The list is checked against the CREATE TABLE statement in ensure_table()
     * by tests/test-analytics-data-guards.php, so it cannot drift away from the
     * schema unnoticed — a hand-kept copy of a schema is otherwise exactly the
     * kind of assertion that ages badly.
     *
     * @since 1.1.0
     *
     * @return array<int, string>
     */
    public static function event_columns(): array {
        return [
            'id',
            'created_at',
            'event_type',
            'ip',
            'path',
            'user_id',
            'user_agent',
            'referrer',
            'plugin',
            'action',
            'form_id',
            'interceptor',
            'reason',
            'verification_data',
            'request_body',
        ];
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

        // The memo may hold a "does not exist" answer from before this call.
        // Reset rather than assume success — dbDelta can fail silently.
        self::$table_exists_memo      = null;
        self::$table_exists_memo_blog = -1;

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
     * @param array<string, mixed> $args Filter args: id, before_id, search, event_type, date_from, date_to.
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

        // DS-9: keyset cursor for callers that walk the whole (ORDER BY id
        // DESC) result set in batches. LIMIT/OFFSET pagination re-runs the
        // query against a table that keeps growing at the head, so every row
        // inserted between two batches shifts the window and makes the
        // previous batch's last rows come back a second time. Anchoring the
        // next batch to the smallest id already seen walks strictly downwards
        // — rows inserted meanwhile get higher ids and are simply not visited.
        $before_id = isset( $args['before_id'] ) ? (int) $args['before_id'] : 0;
        if ( $before_id > 0 ) {
            $where[]  = 'id < %d';
            $params[] = $before_id;
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
     * @param array<string, mixed> $args Filter args (id, before_id, search,
     *                                   event_type, date_from, date_to) plus
     *                                   `limit` (1–1000) and `offset` (>= 0).
     *                                   Pass `before_id` instead of `offset`
     *                                   to page through a growing table
     *                                   without repeating rows.
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

// DS-1: the retention sweep needs a handler that exists on every request that
// may run WP-Cron, not just on requests that log an event — hence file scope,
// the same reasoning as the replay-marker sweep in class-engine.php.
add_action( Analytics::PRUNE_HOOK, [ Analytics::class, 'run_scheduled_prune' ] );

// Re-arm the slot on every request. wp_next_scheduled() reads the autoloaded
// `cron` option, so the common case (slot present) costs no query.
add_action( 'init', [ Analytics::class, 'ensure_prune_schedule' ] );
