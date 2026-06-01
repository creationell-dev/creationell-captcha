<?php
/**
 * IP and user-agent firewall.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Blocks requests by client IP or user-agent before WordPress processes them.
 * See the module-4 design spec §5.
 */
class Firewall {

    /**
     * Runs the firewall for the current request. Registered on `init` at
     * priority 0. Terminates the request when the client is blocked.
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
        if ( empty( $settings['firewall_enabled'] ) ) {
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

        // Editors and administrators are exempt.
        if ( current_user_can( 'edit_posts' ) ) {
            return;
        }

        $context = $this->context( $ip );
        $block   = false;
        $reason  = '';

        if ( creationell_captcha_ip_in_list( $ip, $settings['firewall_ip_block'] ?? [] ) ) {
            $block  = true;
            $reason = __( 'IP-Adresse blockiert', 'creationell-captcha' );
        } elseif ( creationell_captcha_wildcard_match( $context['user_agent'], $settings['firewall_ua_block'] ?? [] ) ) {
            $block  = true;
            $reason = __( 'User-Agent blockiert', 'creationell-captcha' );
        }

        /**
         * Filters the firewall block decision for the current request.
         *
         * @param bool                                                                              $block   Whether to block.
         * @param array{ip: string, path: string, method: string, is_ajax: bool, user_agent: string} $context Request context.
         */
        $block = (bool) apply_filters( 'creationell_captcha_firewall_block', $block, $context );

        if ( ! $block ) {
            return;
        }

        if ( '' === $reason ) {
            $reason = __( 'Firewall-Regel', 'creationell-captcha' );
        }
        $context['reason'] = $reason;

        creationell_captcha_log( 'firewall blocked ' . $ip );

        /**
         * Fires when the firewall blocks an incoming request. Hookable for
         * custom alerting; the default listener in `includes/analytics.php`
         * records the event for the dashboard.
         *
         * @since 0.5.0
         * @param array{ip: string, path: string, method: string, is_ajax: bool, user_agent: string, reason: string} $context Request context with rejection reason.
         */
        do_action( 'creationell_captcha_firewall_blocked', $context );

        creationell_captcha_block_response(
            403,
            __( 'Ihre Anfrage wurde von der Firewall blockiert.', 'creationell-captcha' )
        );
    }

    /**
     * Builds the request context array.
     *
     * @return array{ip: string, path: string, method: string, is_ajax: bool, user_agent: string}
     */
    private function context( string $ip ): array {
        $uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
        $path = (string) wp_parse_url( $uri, PHP_URL_PATH );

        $method = isset( $_SERVER['REQUEST_METHOD'] )
            ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
            : 'GET';

        $is_ajax = isset( $_SERVER['HTTP_X_REQUESTED_WITH'] )
            && 'xmlhttprequest' === strtolower( (string) wp_unslash( $_SERVER['HTTP_X_REQUESTED_WITH'] ) );

        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
            ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] )
            : '';

        return [
            'ip'         => $ip,
            'path'       => $path,
            'method'     => $method,
            'is_ajax'    => $is_ajax,
            'user_agent' => $user_agent,
        ];
    }

}
