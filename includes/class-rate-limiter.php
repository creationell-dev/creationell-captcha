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

        if ( $this->is_challenge_endpoint( $context['path'] ) ) {
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
         * @param array{ip: string, path: string, method: string, script: string, action: string, is_ajax: bool} $context Request context.
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
     * @return array{ip: string, path: string, method: string, script: string, action: string, is_ajax: bool}
     */
    private function context( string $ip ): array {
        $uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
        $path = (string) wp_parse_url( $uri, PHP_URL_PATH );

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
            'ip'      => $ip,
            'path'    => $path,
            'method'  => $method,
            'script'  => $script,
            'action'  => $action,
            'is_ajax' => $is_ajax,
        ];
    }

    /**
     * Whether the request points at the plugin's own challenge endpoint.
     */
    private function is_challenge_endpoint( string $path ): bool {
        if ( str_contains( $path, 'creationell-captcha/v1/challenge' ) ) {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only request classification.
        $rest_route = isset( $_GET['rest_route'] ) ? (string) wp_unslash( $_GET['rest_route'] ) : '';

        return str_contains( $rest_route, 'creationell-captcha/v1/challenge' );
    }

    /**
     * Whether the current request counts toward the rate limit.
     *
     * @param array{ip: string, path: string, method: string, script: string, action: string, is_ajax: bool} $context Request context.
     * @param string                                                                                         $scope   The configured scope.
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
            if ( str_contains( $context['path'], 'contact-form-7/v1' ) ) {
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
