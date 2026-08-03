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
        // BK-9, second call site: the User-Agent branch below spells both
        // polarities of creationell_captcha_wildcard_match() out instead of
        // inheriting them. They ARE the current defaults, so no request is
        // decided differently than before — what was missing was the intent,
        // and that was the point of the finding.
        //
        //  - `false` (empty subject does not match): a request without a
        //    User-Agent header says nothing about its sender, and a BLOCK list
        //    must not turn "nothing known" into "blocked". The bypass call site
        //    in helpers.php passes false as well, but for the opposite reason
        //    (an ALLOW list must not wave an unknown client through) — same
        //    value, different argument, which is why neither side may inherit
        //    it silently.
        //  - `true` (a bare `*` is honoured): in a blocklist it means "block
        //    every client that sends a User-Agent" — drastic, but a deliberate
        //    admin decision and reversible in one click. In the allowlist the
        //    same pattern switched the protection off, which is why it is
        //    refused there.
        } elseif ( creationell_captcha_wildcard_match(
            $context['user_agent'],
            $settings['firewall_ua_block'] ?? [],
            false,
            true
        ) ) {
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
        /*
         * C1, fifth call site. This one was named only in the reviewer's full
         * text and was missing from the consolidated list, so the first fix
         * wave converted four of five places. It used to read
         * `wp_parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH )`, which treats
         * a request target beginning with `//` as a scheme-relative URL and
         * hands back the HOST as the path — `//kontakt/` became `/`,
         * `///kontakt/` became `''`.
         *
         * No firewall decision rides on this value, but it IS the payload of
         * the `creationell_captcha_firewall_block` filter and the
         * `creationell_captcha_firewall_blocked` action: a site-owned filter
         * that decides on `$context['path']` decided on a truncated value, and
         * the event log recorded `/` for a request to `//kontakt/` — for the
         * very request shape the C1 fix exists to catch.
         */
        $path = creationell_captcha_request_path();

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
