<?php
/**
 * Per-IP request rate limiter.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Counts requests per client IP in a fixed time window and blocks with HTTP
 * 429 once the configured limit is exceeded. See the module-4 design spec §6.
 */
class RateLimiter {

    /**
     * The plugin's own challenge route — the only route exempt from counting.
     * Compared for EQUALITY against the route the request actually addresses
     * (CM-7); the previous `str_contains()` matched any path or `rest_route`
     * value that merely contained this string.
     */
    private const CHALLENGE_ROUTE = '/creationell-captcha/v1/challenge';

    /**
     * Runs the rate limiter for the current request. Registered on `init` at
     * priority 0. Terminates the request with 429 once the limit is exceeded.
     */
    public function run(): void {
        if ( creationell_captcha_is_disabled() ) {
            return;
        }
        if ( 'cli' === php_sapi_name()
            || ( defined( 'DOING_CRON' ) && DOING_CRON )
            || ( defined( 'WP_CLI' ) && WP_CLI )
        ) {
            return;
        }

        $settings = creationell_captcha_get_settings();
        if ( empty( $settings['ratelimit_enabled'] ) ) {
            return;
        }

        $ip = creationell_captcha_get_client_ip();
        if ( '' === $ip ) {
            return;
        }

        // Allowlist (IP / UA / Cookie) wins over everything — lockout safety.
        if ( false !== creationell_captcha_request_bypassed() ) {
            return;
        }

        if ( current_user_can( 'edit_posts' ) ) {
            return;
        }

        $context = $this->context( $ip );

        if ( $this->is_challenge_endpoint() ) {
            return;
        }
        if ( ! $this->should_count( $context, (string) ( $settings['ratelimit_scope'] ?? 'core' ) ) ) {
            return;
        }

        $window = max( 10, min( 3600, (int) ( $settings['ratelimit_window'] ?? 300 ) ) );
        $max    = max( 1, (int) ( $settings['ratelimit_max'] ?? 10 ) );

        $bucket = (int) floor( time() / $window );
        $key    = 'creationell_captcha_rl_' . substr( hash( 'sha256', $ip ), 0, 32 ) . '_' . $bucket;

        // Get/set is not atomic — an accepted trade-off (spec §6).
        $count = (int) get_transient( $key ) + 1;
        set_transient( $key, $count, $window );

        if ( $count <= $max ) {
            return;
        }

        $retry_after = max( 1, ( ( $bucket + 1 ) * $window ) - time() );

        creationell_captcha_log( 'rate limit exceeded for ' . $ip );

        /**
         * Fires when a request triggers the per-IP rate limiter. Hookable
         * for custom alerting (Slack, email, …). The default listener in
         * `includes/analytics.php` records the event for the dashboard.
         *
         * @since 0.5.0
         * @param array{ip: string, path: string, path_raw: string, method: string, script: string, action: string, is_ajax: bool} $context Request context.
         */
        do_action( 'creationell_captcha_ratelimit_exceeded', $context );

        creationell_captcha_block_response(
            429,
            __( 'Zu viele Anfragen. Bitte versuchen Sie es später erneut.', 'creationell-captcha' ),
            $retry_after
        );
    }

    /**
     * Builds the request context array.
     *
     * @return array{ip: string, path: string, path_raw: string, method: string, script: string, action: string, is_ajax: bool}
     */
    private function context( string $ip ): array {
        // C1: same request-path root as the interceptor. With wp_parse_url()
        // the scope `forms` lost its CF7 window for the `//` spelling — the
        // substring checks in should_count() ran against a path the parser had
        // truncated to the part after the pseudo-host.
        $raw_path = creationell_captcha_request_path();

        // BK-5, same raw-path assumption as in the interceptor: decode exactly
        // once, after the query has been split off, so `should_count()` sees
        // the path WordPress routes on. Percent-encoding a counted endpoint
        // (e.g. `contact%2Dform%2D7/v1`) must not drop it out of the window.
        //
        // The raw spelling is kept alongside, because decoding is not a
        // superset either: `/%2contact-form-7/v1/…` CONTAINS the counted
        // substring while raw and loses it when decoded (`%2c` → ','). Up to
        // 1.0.2 only the raw spelling was checked, so checking just the decoded
        // one would have quietly stopped counting such requests.
        $path = rawurldecode( $raw_path );

        $method = isset( $_SERVER['REQUEST_METHOD'] )
            ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
            : 'GET';

        $script = isset( $_SERVER['SCRIPT_NAME'] )
            ? basename( (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) )
            : '';

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only request classification.
        $action = isset( $_POST['action'] ) ? (string) wp_unslash( $_POST['action'] ) : '';

        $is_ajax = isset( $_SERVER['HTTP_X_REQUESTED_WITH'] )
            && 'xmlhttprequest' === strtolower( (string) wp_unslash( $_SERVER['HTTP_X_REQUESTED_WITH'] ) );

        return [
            'ip'       => $ip,
            'path'     => $path,
            'path_raw' => $raw_path,
            'method'   => $method,
            'script'   => $script,
            'action'   => $action,
            'is_ajax'  => $is_ajax,
        ];
    }

    /**
     * Whether the request is actually served by the plugin's own challenge
     * endpoint — the one route that must stay reachable without being counted,
     * because the widget fetches a challenge for every protected form.
     *
     * BK-2 / CM-7: the previous implementation ran `str_contains()` over the
     * request path AND over the raw `$_GET['rest_route']` value. Both are
     * client-controlled, and neither says anything about what WordPress will
     * actually serve: `POST /wp-login.php?rest_route=creationell-captcha/v1/challenge`
     * is an ordinary login POST — wp-login.php never calls parse_request(), so
     * rest_api_loaded() never runs — yet it turned the rate limiter off and
     * made the login brute-force limit unenforceable.
     *
     * The route now comes from creationell_captcha_current_rest_route(), which
     * only reports a route when core would really dispatch one, and it is
     * compared for equality instead of by substring.
     */
    private function is_challenge_endpoint(): bool {
        return self::CHALLENGE_ROUTE === creationell_captcha_current_rest_route();
    }

    /**
     * Whether the current request counts toward the rate limit.
     *
     * @param array{ip: string, path: string, path_raw: string, method: string, script: string, action: string, is_ajax: bool} $context Request context.
     * @param string                                                                                                           $scope   The configured scope.
     */
    private function should_count( array $context, string $scope ): bool {
        if ( 'all' === $scope ) {
            return ! is_admin();
        }

        // `core` and `forms` both count POSTs to the WP auth/comment endpoints.
        if ( 'POST' === $context['method']
            && in_array( $context['script'], [ 'wp-login.php', 'wp-comments-post.php' ], true )
        ) {
            return true;
        }

        if ( 'forms' === $scope && 'POST' === $context['method'] ) {
            // Both spellings — decoding is neither a subset nor a superset of
            // the raw path (see self::context()), and counting a request too
            // many is the harmless direction.
            if ( str_contains( $context['path'], 'contact-form-7/v1' )
                || str_contains( $context['path_raw'], 'contact-form-7/v1' )
            ) {
                return true;
            }
            if ( 'admin-ajax.php' === $context['script']
                && str_starts_with( $context['action'], 'forminator_submit_form' )
            ) {
                return true;
            }
        }

        return false;
    }
}
