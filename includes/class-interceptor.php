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
     * Request-local cache of the filtered action patterns. The filter is
     * evaluated in exactly one place (self::action_patterns()) and exactly
     * once per request, so the bypass step and the guard step can never see
     * two different lists — that asymmetry was BK-10.
     *
     * @var array<int, string>|null
     */
    private ?array $action_patterns = null;

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
             * @param array{path: string, path_raw: string, method: string, script: string, is_ajax: bool, action: string, actions: array<int, string>} $context Request context.
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
         * @param array{path: string, path_raw: string, method: string, script: string, is_ajax: bool, action: string, actions: array<int, string>} $context Request context.
         */
        do_action( 'creationell_captcha_interceptor_blocked', $context );
        $this->fail( $context );
    }

    /**
     * Builds the request context.
     *
     * `action` keeps the historic single-value shape (POST preferred) for the
     * event payloads; `actions` carries BOTH candidate sources, because the
     * guard has to consider both — see below. `path` is the URL-decoded path,
     * `path_raw` the wire spelling; the guard matches against both (BK-5, see
     * self::match_request_path()).
     *
     * @return array{path: string, path_raw: string, method: string, script: string, is_ajax: bool, action: string, actions: array<int, string>}
     */
    private function context(): array {
        /*
         * C1: the path comes from the shared request-path root, NOT from
         * wp_parse_url(). The latter reads `//kontakt/` as a scheme-relative
         * URL and hands back `/` (host = "kontakt"), while WP::parse_request()
         * collapses the leading slashes and serves the very same page — so
         * `POST //kontakt` matched no pattern and walked straight past this
         * guard. See creationell_captcha_request_path() for the full account.
         */
        $raw_path = creationell_captcha_request_path();

        /*
         * BK-5: also match on the URL-decoded path. WordPress core routes
         * /%6Bontakt and /kontakt to the same page — WP::parse_request()
         * retries every rewrite rule against urldecode( $request_match )
         * (wp-includes/class-wp.php:239-241) — while the interceptor used to
         * see the raw path only and matched neither the exact nor the wildcard
         * pattern.
         *
         * Decoded EXACTLY ONCE, and only after the query has been split off:
         * a double-encoded /%256Bontakt must stay /%6Bontakt and
         * must NOT collapse to /kontakt, because core does not route it there
         * either. Decoding twice would guard a path core never resolves to
         * the pattern's target, and — worse — would let a `!`-exclusion
         * pattern be hit by an input core routes elsewhere.
         *
         * Both spellings are carried, and both are matched — see
         * self::match_request_path() for why replacing the raw path would
         * silently drop protection on existing installations.
         */
        $path = rawurldecode( $raw_path );

        $method = isset( $_SERVER['REQUEST_METHOD'] )
            ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
            : 'GET';

        $script = isset( $_SERVER['SCRIPT_NAME'] )
            ? basename( (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) )
            : '';

        /*
         * BK-11: admin-ajax.php and admin-post.php dispatch on
         * $_REQUEST['action'], whose composition depends on the `request_order`
         * INI setting. Preferring $_POST['action'] therefore looked at a
         * different value than the dispatcher under request_order='PG': a
         * guarded action in the query string plus a harmless one in the body
         * ran the guarded handler unguarded.
         *
         * Both sources are collected and the guard matches if EITHER of them
         * hits a protected pattern (fail-closed). That is independent of any
         * INI setting and of which one core happens to dispatch on.
         */
        $candidates = [];
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- action is matched against admin-configured patterns, not echoed.
        if ( isset( $_POST['action'] ) && is_scalar( $_POST['action'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $candidates[] = (string) wp_unslash( $_POST['action'] );
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( isset( $_GET['action'] ) && is_scalar( $_GET['action'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $candidates[] = (string) wp_unslash( $_GET['action'] );
        }

        $actions = [];
        foreach ( $candidates as $candidate ) {
            $clean = substr( sanitize_text_field( $candidate ), 0, 64 );
            if ( '' !== $clean && ! in_array( $clean, $actions, true ) ) {
                $actions[] = $clean;
            }
        }

        return [
            'path'     => $path,
            'path_raw' => $raw_path,
            'method'   => $method,
            'script'   => $script,
            'is_ajax'  => $this->is_ajax_request(),
            'action'   => $actions[0] ?? '',
            'actions'  => $actions,
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
     * @param array{path: string, path_raw: string, method: string, script: string, is_ajax: bool, action: string, actions: array<int, string>} $context Request context.
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
        //
        // BK-10: reads the SAME filtered list as is_guarded() does. Reading
        // the raw settings here while the guard applied
        // `creationell_captcha_interceptor_actions` meant a pattern added only
        // via the filter never overrode the is_admin() bypass — the request
        // was silently unprotected in admin-post.php/admin-ajax.php.
        $override_is_admin = $this->matches_action( $context, $this->action_patterns() );

        // 5. Admin area — also covers wp-admin/admin-ajax.php. Skipped when
        //    an action pattern matches (named-action endpoints typically live
        //    in wp-admin/admin-post.php).
        if ( is_admin() && ! $override_is_admin ) {
            return true;
        }

        // 6. REST requests — keeps the module-1 challenge endpoint reachable.
        if ( $this->is_rest_request() ) {
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
         * @param bool                                                                                                       $bypass  Whether to bypass. Default false.
         * @param array{path: string, path_raw: string, method: string, script: string, is_ajax: bool, action: string, actions: array<int, string>} $context Request context.
         */
        return (bool) apply_filters( 'creationell_captcha_interceptor_bypass', false, $context );
    }

    /**
     * Whether the current request is served by the WordPress REST API.
     *
     * The REST_REQUEST constant is not yet defined at `init` priority 1 — core
     * only defines it inside rest_api_loaded(), which runs on `parse_request`,
     * i.e. after `init`. That is still true, so the constant remains unusable
     * here and the request has to be identified from its own shape.
     *
     * BK-1: the previous implementation did that with a bare
     * `isset( $_GET['rest_route'] )` — value-independent, so a trailing
     * `?rest_route=` on ANY request switched the whole interceptor off while
     * core, seeing an empty value, bailed out of rest_api_loaded() and served
     * the page normally. The decision now lives in
     * creationell_captcha_current_rest_route(), which evaluates the VALUE and
     * the serving entry point exactly the way core does.
     */
    private function is_rest_request(): bool {
        return '' !== creationell_captcha_current_rest_route();
    }

    /**
     * The filtered action-slug patterns — the single evaluation point for
     * `creationell_captcha_interceptor_actions` (BK-10). Cached per request so
     * the bypass step and the guard step can never disagree, not even with a
     * non-deterministic filter callback attached.
     *
     * @return array<int, string>
     */
    private function action_patterns(): array {
        if ( null !== $this->action_patterns ) {
            return $this->action_patterns;
        }

        $settings = creationell_captcha_get_settings();

        $action_patterns = isset( $settings['interceptor_actions'] ) && is_array( $settings['interceptor_actions'] )
            ? $settings['interceptor_actions']
            : [];

        /**
         * Filters the WordPress action-slug patterns (read from `$_POST['action']`
         * / `$_GET['action']`) that the interceptor guards. Same wildcard/exclude
         * semantics as `creationell_captcha_interceptor_paths`.
         *
         * The returned list drives BOTH the guard decision and the override of
         * the `is_admin()` bypass step, so a pattern added here also protects
         * wp-admin/admin-post.php and admin-ajax.php endpoints.
         *
         * @since 0.18.0
         * @param array<int, string> $action_patterns Wildcard patterns from settings.
         */
        /** @var array<int, string> $filtered */
        $filtered = (array) apply_filters( 'creationell_captcha_interceptor_actions', $action_patterns );

        $this->action_patterns = $filtered;

        return $filtered;
    }

    /**
     * Whether any of the request's action candidates matches a pattern.
     *
     * BK-11: a request counts as protected when EITHER $_POST['action'] or
     * $_GET['action'] hits a guarded pattern, regardless of which one core's
     * $_REQUEST-based dispatcher would pick under the active `request_order`.
     *
     * @param array{action: string, actions: array<int, string>} $context  Request context.
     * @param array<int, string>                                 $patterns Wildcard patterns.
     */
    private function matches_action( array $context, array $patterns ): bool {
        if ( empty( $patterns ) ) {
            return false;
        }

        foreach ( $context['actions'] as $action ) {
            if ( '' === $action ) {
                continue;
            }
            if ( self::match_path( $action, $patterns ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the current request is a guarded target. Checks both URL paths
     * (`interceptor_paths`) and action slugs (`interceptor_actions`); a positive
     * match in either list guards the request.
     *
     * @param array{path: string, path_raw: string, method: string, script: string, is_ajax: bool, action: string, actions: array<int, string>} $context Request context.
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

        // Documented in Interceptor::action_patterns() — the single place the
        // `creationell_captcha_interceptor_actions` filter is evaluated.
        $guarded = self::match_request_path( $context['path'], $context['path_raw'], $path_patterns );

        if ( ! $guarded ) {
            $guarded = $this->matches_action( $context, $this->action_patterns() );
        }

        /**
         * Filters the final "is this request guarded by the interceptor"
         * decision. Runs AFTER the path/action pattern matching, so it
         * sees the resolved boolean. Return `true` to force-guard, `false`
         * to force-skip.
         *
         * @since 0.18.0
         * @param bool                                                                                                       $guarded Whether the request matched a guard pattern.
         * @param array{path: string, path_raw: string, method: string, script: string, is_ajax: bool, action: string, actions: array<int, string>} $context Request context.
         */
        return (bool) apply_filters( 'creationell_captcha_interceptor_guarded', $guarded, $context );
    }

    /**
     * Matches a request path against the pattern list in BOTH spellings the
     * request can have: URL-decoded and as it came off the wire.
     *
     * BK-5 asked for matching on the DECODED path, because core routes
     * /%6Bontakt and /kontakt to the same page. Decoding alone, however, would
     * have been a one-way replacement, and that silently REMOVES protection on
     * updating installations: up to 1.0.2 the matching ran on the raw path, so
     * for every page whose slug is not plain ASCII (Cyrillic/Greek/CJK stay
     * UTF-8 in a WordPress slug) the percent-encoded pattern was the only
     * configuration that ever worked. `interceptor_paths = ['/%C3%BCber-uns*']`
     * guarding the page `/über-uns` matched `POST /%C3%BCber-uns` before, and
     * would have stopped matching it after a decode-only change — the exact
     * silent hole this audit is about, only in the other direction.
     *
     * Hence OR, not replace. The OR can only ever guard MORE requests, never
     * fewer, so it cannot open a bypass. Its price: an exclusion (`!…`) written
     * in one spelling no longer suppresses a positive match found in the other
     * spelling — e.g. `!/kontakt/admin` does not exclude `/kontakt/%61dmin`,
     * which the raw pass still matches via `/kontakt*`. That request is then
     * guarded rather than let through, which is fail-closed and exactly the
     * 1.0.2 behaviour.
     *
     * @param string             $decoded_path Path decoded exactly once (see self::context()).
     * @param string             $raw_path     Path as sent, still percent-encoded.
     * @param array<int, string> $patterns     Wildcard patterns; `!`-prefixed = exclude.
     */
    public static function match_request_path( string $decoded_path, string $raw_path, array $patterns ): bool {
        if ( self::match_path( $decoded_path, $patterns ) ) {
            return true;
        }

        if ( $raw_path === $decoded_path ) {
            return false;
        }

        return self::match_path( $raw_path, $patterns );
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
     * Matches ONE spelling of a path. Callers that hold a request path use
     * self::match_request_path() instead, which runs this against the decoded
     * and the raw spelling (BK-5); calling it with a single spelling would
     * either lose the percent-encoded patterns of existing configurations or
     * the pages core routes through decoding.
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
     * @param array{path: string, path_raw: string, method: string, script: string, is_ajax: bool} $context Request context.
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
