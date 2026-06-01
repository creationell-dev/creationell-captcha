<?php
/**
 * Generic server-side request guard — the interceptor.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Inspects front-end POST requests and enforces a valid ALTCHA payload for
 * requests whose path matches a configured pattern. See the module-2 design
 * spec for the bypass chain (§6) and the guard decision (§7/§8).
 */
class Interceptor {

    /**
     * Script basenames that are never guarded. The module-1 core-form
     * integrations own these; a second verification here would consume the
     * challenge and make the subsequent hook verification fail as a replay.
     */
    private const EXCLUDED_SCRIPTS = [
        'wp-login.php',
        'wp-comments-post.php',
        'wp-cron.php',
        'xmlrpc.php',
    ];

    /**
     * Runs the interceptor for the current request. Registered on `init` at
     * priority 1. Terminates the request when verification fails.
     */
    public function run(): void {
        $context = $this->context();

        if ( $this->should_bypass( $context ) ) {
            return;
        }

        if ( ! $this->is_guarded( $context ) ) {
            return;
        }

        if ( creationell_captcha_verify_request() ) {
            /**
             * Fires when a guarded interceptor request passes the captcha
             * check. The default listener in `includes/analytics.php`
             * records it as a `verified`/`interceptor` event.
             *
             * @since 0.3.0
             * @param array{path: string, method: string, script: string, is_ajax: bool, action: string} $context Request context.
             */
            do_action( 'creationell_captcha_interceptor_passed', $context );
            return;
        }

        /**
         * Fires when a guarded interceptor request fails the captcha
         * check. The default listener in `includes/analytics.php` records
         * it as a `failed`/`interceptor` event.
         *
         * @since 0.3.0
         * @param array{path: string, method: string, script: string, is_ajax: bool, action: string} $context Request context.
         */
        do_action( 'creationell_captcha_interceptor_blocked', $context );
        $this->fail( $context );
    }

    /**
     * Builds the request context. Adds an `action` field read from
     * $_POST['action'] (preferred) or $_GET['action'] for action-based protection.
     *
     * @return array{path: string, method: string, script: string, is_ajax: bool, action: string}
     */
    private function context(): array {
        $uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

        // wp_parse_url() yields null for an absent path and false for an
        // unparseable URL; the (string) cast normalises both to ''. A guarded
        // empty path then fails closed, which is the correct outcome.
        $path = (string) wp_parse_url( $uri, PHP_URL_PATH );

        $method = isset( $_SERVER['REQUEST_METHOD'] )
            ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
            : 'GET';

        $script = isset( $_SERVER['SCRIPT_NAME'] )
            ? basename( (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) )
            : '';

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- action is matched against admin-configured patterns, not echoed.
        $raw_action = '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( isset( $_POST['action'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $raw_action = (string) wp_unslash( $_POST['action'] );
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        } elseif ( isset( $_GET['action'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $raw_action = (string) wp_unslash( $_GET['action'] );
        }
        $action = substr( sanitize_text_field( $raw_action ), 0, 64 );

        return [
            'path'    => $path,
            'method'  => $method,
            'script'  => $script,
            'is_ajax' => $this->is_ajax_request(),
            'action'  => $action,
        ];
    }

    /**
     * Best-effort detection of a JSON/AJAX request.
     */
    private function is_ajax_request(): bool {
        $requested_with = isset( $_SERVER['HTTP_X_REQUESTED_WITH'] )
            ? strtolower( (string) wp_unslash( $_SERVER['HTTP_X_REQUESTED_WITH'] ) )
            : '';
        if ( 'xmlhttprequest' === $requested_with ) {
            return true;
        }

        $accept = isset( $_SERVER['HTTP_ACCEPT'] )
            ? strtolower( (string) wp_unslash( $_SERVER['HTTP_ACCEPT'] ) )
            : '';

        return str_contains( $accept, 'application/json' );
    }

    /**
     * The bypass chain. Evaluation order = listing order. Action-based
     * protection overrides the `is_admin()` step (and only that step) so
     * named-action endpoints in wp-admin/admin-post.php and admin-ajax.php
     * can be guarded.
     *
     * @param array{path: string, method: string, script: string, is_ajax: bool, action: string} $context Request context.
     */
    private function should_bypass( array $context ): bool {
        // 1. Kill switch (module-1 wp-config constant).
        if ( creationell_captcha_is_disabled() ) {
            return true;
        }

        $settings = creationell_captcha_get_settings();

        // 2. Master toggle.
        if ( empty( $settings['interceptor_enabled'] ) ) {
            return true;
        }

        // 3. Only POST requests are guarded.
        if ( 'POST' !== $context['method'] ) {
            return true;
        }

        // 4. CLI / cron / WP-CLI / XML-RPC.
        if ( 'cli' === php_sapi_name()
            || ( defined( 'DOING_CRON' ) && DOING_CRON )
            || ( defined( 'WP_CLI' ) && WP_CLI )
            || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
        ) {
            return true;
        }

        // Action-based protection overrides the is_admin() step below. All
        // other steps remain in effect — edit_posts, REST, etc. — so trusted
        // users are still exempt even when an action pattern matches.
        $action_patterns   = (array) ( $settings['interceptor_actions'] ?? [] );
        $override_is_admin = ( ! empty( $action_patterns )
            && '' !== $context['action']
            && self::match_path( $context['action'], $action_patterns )
        );

        // 5. Admin area — also covers wp-admin/admin-ajax.php. Skipped when
        //    an action pattern matches (named-action endpoints typically live
        //    in wp-admin/admin-post.php).
        if ( is_admin() && ! $override_is_admin ) {
            return true;
        }

        // 6. REST requests — keeps the module-1 challenge endpoint reachable.
        if ( $this->is_rest_request( $context['path'] ) ) {
            return true;
        }

        // 7. Core-form scripts owned by the module-1 integrations.
        if ( in_array( $context['script'], self::EXCLUDED_SCRIPTS, true ) ) {
            return true;
        }

        // 8. Users who can edit posts (editors, authors, admins).
        if ( current_user_can( 'edit_posts' ) ) {
            return true;
        }

        // 9. Optional: skip all logged-in users.
        if ( ! empty( $settings['interceptor_skip_logged_in'] ) && is_user_logged_in() ) {
            return true;
        }

        // 10. Global bypass (IP allowlist, UA bypass, cookie bypass).
        if ( false !== creationell_captcha_request_bypassed() ) {
            return true;
        }

        // 11. Developer escape hatch.
        /**
         * Filters whether the interceptor should bypass the captcha check
         * for the current request. Returning `true` skips the check —
         * Developer-API escape hatch for custom rules that none of the
         * built-in bypass steps cover.
         *
         * Runs LAST in the bypass chain (after all built-in checks). Code
         * that hooks this should be defensive: a wrongly returning `true`
         * here disables protection on guarded paths.
         *
         * @since 0.3.0
         * @param bool                                                                                  $bypass  Whether to bypass. Default false.
         * @param array{path: string, method: string, script: string, is_ajax: bool, action: string}    $context Request context.
         */
        return (bool) apply_filters( 'creationell_captcha_interceptor_bypass', false, $context );
    }

    /**
     * Whether the request path points at the REST API.
     */
    private function is_rest_request( string $path ): bool {
        // The REST_REQUEST constant is not yet defined at `init` priority 1,
        // so the request is identified by its URL shape instead.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- presence check only.
        if ( isset( $_GET['rest_route'] ) ) {
            return true;
        }

        $prefix = trim( (string) rest_get_url_prefix(), '/' );
        if ( '' === $prefix ) {
            return false;
        }

        return 1 === preg_match( '#(^|/)' . preg_quote( $prefix, '#' ) . '(/|$)#', $path );
    }

    /**
     * Whether the current request is a guarded target. Checks both URL paths
     * (`interceptor_paths`) and action slugs (`interceptor_actions`); a positive
     * match in either list guards the request.
     *
     * @param array{path: string, method: string, script: string, is_ajax: bool, action: string} $context Request context.
     */
    private function is_guarded( array $context ): bool {
        $settings = creationell_captcha_get_settings();

        $path_patterns = isset( $settings['interceptor_paths'] ) && is_array( $settings['interceptor_paths'] )
            ? $settings['interceptor_paths']
            : [];
        /**
         * Filters the URL-path patterns that the interceptor guards. Patterns
         * support `*`-wildcards and `!`-prefixed exclusions; the runtime
         * settings list is the input — return an extended/restricted list
         * to add/remove guarded paths at runtime.
         *
         * @since 0.3.0
         * @param array<int, string> $path_patterns Wildcard patterns from settings.
         */
        /** @var array<int, string> $path_patterns */
        $path_patterns = (array) apply_filters( 'creationell_captcha_interceptor_paths', $path_patterns );

        $action_patterns = isset( $settings['interceptor_actions'] ) && is_array( $settings['interceptor_actions'] )
            ? $settings['interceptor_actions']
            : [];
        /**
         * Filters the WordPress action-slug patterns (read from `$_POST['action']`
         * / `$_GET['action']`) that the interceptor guards. Same wildcard/exclude
         * semantics as `creationell_captcha_interceptor_paths`.
         *
         * @since 0.18.0
         * @param array<int, string> $action_patterns Wildcard patterns from settings.
         */
        /** @var array<int, string> $action_patterns */
        $action_patterns = (array) apply_filters( 'creationell_captcha_interceptor_actions', $action_patterns );

        $guarded = self::match_path( $context['path'], $path_patterns );

        if ( ! $guarded && '' !== $context['action'] && ! empty( $action_patterns ) ) {
            $guarded = self::match_path( $context['action'], $action_patterns );
        }

        /**
         * Filters the final "is this request guarded by the interceptor"
         * decision. Runs AFTER the path/action pattern matching, so it
         * sees the resolved boolean. Return `true` to force-guard, `false`
         * to force-skip.
         *
         * @since 0.18.0
         * @param bool                                                                                  $guarded Whether the request matched a guard pattern.
         * @param array{path: string, method: string, script: string, is_ajax: bool, action: string}    $context Request context.
         */
        return (bool) apply_filters( 'creationell_captcha_interceptor_guarded', $guarded, $context );
    }

    /**
     * Matches a request path against a list of `*`-wildcard patterns, with
     * `!`-prefixed entries acting as hard exclusions (allow-list semantics).
     *
     * Returns true iff at least one positive pattern matches AND no `!`-pattern
     * matches. Order in the list is irrelevant — a single `!`-match short-circuits
     * the whole list to false.
     *
     * Public and static so the matching can be exercised in isolation; also
     * reused for action-name matching (the algorithm is charset-agnostic).
     *
     * @param string             $path     Request path or action slug.
     * @param array<int, string> $patterns Wildcard patterns; `!`-prefixed = exclude.
     */
    public static function match_path( string $path, array $patterns ): bool {
        $matched_positive = false;

        foreach ( $patterns as $pattern ) {
            $pattern = trim( (string) $pattern );
            if ( '' === $pattern ) {
                continue;
            }

            $is_exclude = false;
            if ( '!' === $pattern[0] ) {
                $is_exclude = true;
                $pattern    = substr( $pattern, 1 );
                if ( '' === $pattern ) {
                    continue;
                }
            }

            $regex = '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#i';
            if ( 1 === preg_match( $regex, $path ) ) {
                if ( $is_exclude ) {
                    // Hard exclude — the entire list evaluates to false.
                    return false;
                }
                $matched_positive = true;
            }
        }

        return $matched_positive;
    }

    /**
     * Sends the fail-closed response and terminates the request — see spec §10.
     *
     * @param array{path: string, method: string, script: string, is_ajax: bool} $context Request context.
     */
    private function fail( array $context ): void {
        creationell_captcha_log( 'interceptor blocked POST to ' . $context['path'] );

        $message = __(
            'Die Sicherheitsabfrage wurde nicht bestanden. Bitte gehen Sie zurück und versuchen Sie es erneut.',
            'creationell-captcha'
        );

        if ( $context['is_ajax'] ) {
            wp_send_json_error( [ 'message' => $message ], 403 ); // Terminates the request.
        }

        wp_die(
            esc_html( $message ),
            esc_html__( 'Sicherheitsabfrage fehlgeschlagen', 'creationell-captcha' ),
            [
                'response'  => 403,
                'back_link' => true,
            ]
        );
    }
}
