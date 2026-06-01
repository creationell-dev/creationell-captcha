<?php
/**
 * Challenge REST endpoint.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers the public challenge route.
 */
function creationell_captcha_register_rest_routes(): void {
    if ( creationell_captcha_is_disabled() ) {
        return;
    }

    register_rest_route(
        'creationell-captcha/v1',
        '/challenge',
        [
            'methods'             => 'GET',
            'callback'            => 'creationell_captcha_rest_challenge',
            'permission_callback' => '__return_true',
        ]
    );
}
add_action( 'rest_api_init', 'creationell_captcha_register_rest_routes' );

/**
 * Returns a fresh, single-use challenge. Records the issuance via the standard
 * event channel — aggregate counters always increment, the detail-log entry
 * is gated by the `log_challenge` per-type toggle from Modul 11c.
 *
 * @param WP_REST_Request $request The REST request. Optional query parameter
 *                                 `ctx` (HMAC token, used by the under-attack
 *                                 interstitial to suppress the code-challenge
 *                                 attachment).
 * @return WP_REST_Response JSON challenge envelope with `algorithm`, `challenge`,
 *                          `salt`, `signature`, `parameters` and optional
 *                          `codeChallenge.image` URL.
 */
function creationell_captcha_rest_challenge( WP_REST_Request $request ): WP_REST_Response {
    // The under-attack interstitial signals an HMAC-token ctx so we skip the
    // code-challenge attachment — its widget is display="invisible" and
    // cannot show a code modal. The token is over the current 5-min bucket,
    // verifier accepts current OR previous bucket for clock tolerance. An
    // attacker cannot forge it without the plugin's HMAC secret, so the
    // suppression cannot be triggered by an arbitrary client.
    $ctx                 = (string) $request->get_param( 'ctx' );
    $skip_code_challenge = false;
    if ( '' !== $ctx ) {
        $secret  = creationell_captcha_get_hmac_secret();
        $b_curr  = (int) floor( time() / 300 );
        $expect1 = hash_hmac( 'sha256', 'ua-ctx|' . $b_curr, $secret );
        $expect2 = hash_hmac( 'sha256', 'ua-ctx|' . ( $b_curr - 1 ), $secret );
        $skip_code_challenge = hash_equals( $expect1, $ctx ) || hash_equals( $expect2, $ctx );
    }

    $challenge = creationell_captcha_engine()->create_challenge();

    // Modul 15: attach a code-challenge instruction when triggers match.
    // Embeds the token both in parameters.data.ccode (so it round-trips
    // back to us via the PoW payload) and in the image URL query (so
    // /code-image can render the PNG without state lookup duplication).
    $challenge['codeChallenge'] = null;
    if ( ! $skip_code_challenge
        && function_exists( 'creationell_captcha_should_issue_code_challenge' )
        && creationell_captcha_should_issue_code_challenge() ) {
        $settings = creationell_captcha_get_settings();
        $expiry   = max( 60, min( 900, (int) ( $settings['code_challenge_expiry'] ?? 300 ) ) );
        $code     = creationell_captcha_generate_code();
        $token    = creationell_captcha_code_token_issue( $code, $expiry );

        // Embed in parameters.data so the ALTCHA-lib signature covers it.
        if ( ! isset( $challenge['parameters']['data'] ) || ! is_array( $challenge['parameters']['data'] ) ) {
            $challenge['parameters']['data'] = [];
        }
        $challenge['parameters']['data']['ccode'] = $token;

        // Re-sign because we mutated parameters after the initial signing.
        // HMAC algo + format follow `Altcha->hmacHex()` from altcha-lib-php
        // (SHA-256, hex output) over the canonical-JSON form of parameters.
        $sig_secret = creationell_captcha_get_hmac_secret();
        if ( '' !== $sig_secret ) {
            $challenge['signature'] = hash_hmac(
                'sha256',
                creationell_captcha_canonical_params_json( $challenge['parameters'] ),
                $sig_secret
            );
        }

        $challenge['codeChallenge'] = [
            'image' => rest_url( 'creationell-captcha/v1/code-image' ) . '?t=' . rawurlencode( $token ),
        ];
    }

    /**
     * Fires whenever a security-relevant request crosses one of the plugin's
     * gates. The recorder in `includes/analytics.php` (registered as a default
     * listener) updates the aggregate counters and — when the detailed
     * event-log toggle is on — writes a row to the events table. Third-party
     * integrations may hook this to emit notifications, ship logs to SIEM, etc.
     *
     * The first argument is one of the canonical types:
     *  - `verified`    — request passed (PoW solution good OR matched a bypass)
     *  - `failed`      — PoW solution missing/invalid
     *  - `firewall`    — IP/UA blocklist hit
     *  - `ratelimit`   — per-IP request bucket exhausted
     *  - `underattack` — under-attack interstitial served
     *  - `underattack_passed` — under-attack challenge solved, pass cookie issued
     *  - `challenge`   — challenge issued via REST `/challenge`
     *
     * The context array carries diagnostic keys; supported (all optional):
     * `plugin`, `action`, `form_id`, `reason`, `interceptor` (bool). Modules
     * may add extra keys; the recorder stores known fields into typed
     * columns and ignores the rest.
     *
     * @since 0.6.0
     * @param string               $type    Event type — see the list above.
     * @param array<string, mixed> $context Optional diagnostic context.
     */
    do_action(
        'creationell_captcha_event',
        'challenge',
        [
            'action' => 'challenge',
        ]
    );

    $response = new WP_REST_Response( $challenge );
    $response->header( 'Cache-Control', 'no-store, max-age=0' );

    return $response;
}

/**
 * Canonical-JSON serialisation of ALTCHA challenge parameters, byte-
 * identical to `altcha-lib-php`'s `ChallengeParameters::toCanonicalJson()`
 * (= ksort top-level + recursive ksort on assoc sub-arrays, JSON-encoded
 * with UNESCAPED_SLASHES | UNESCAPED_UNICODE, null keys dropped).
 *
 * Needed for the re-sign step in Modul 15's /challenge handler after we
 * mutate parameters.data.ccode.
 *
 * @param array<string, mixed> $params Parameter array from `create_challenge()`.
 */
function creationell_captcha_canonical_params_json( array $params ): string {
    $clean = [];
    foreach ( $params as $k => $v ) {
        if ( null === $v ) {
            continue;
        }
        $clean[ $k ] = $v;
    }
    ksort( $clean );
    creationell_captcha_canonical_sort_recursive( $clean );

    return (string) wp_json_encode(
        $clean,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}

/**
 * Recursive helper used by `canonical_params_json` — mirrors the lib's
 * `sortRecursive`. List arrays (sequential integer keys) keep their order;
 * associative arrays get `ksort`-ed in place.
 *
 * @param array<mixed> $data
 */
function creationell_captcha_canonical_sort_recursive( array &$data ): void {
    foreach ( $data as &$value ) {
        if ( is_array( $value ) && ! array_is_list( $value ) ) {
            ksort( $value );
            creationell_captcha_canonical_sort_recursive( $value );
        }
    }
}
