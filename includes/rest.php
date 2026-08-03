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
 *
 * REST-GATE-OK: /challenge is deliberately public (permission_callback
 * __return_true) — it is the shared entry point that issues a fresh,
 * single-use PoW challenge for ALL captcha types, not a feature specific
 * to one toggle. It remains subject to the global kill switch
 * (creationell_captcha_is_disabled()) below.
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
            // CM-10: without a schema `?ctx[]=1` reached the handler as an
            // array and the `(string)` cast raised an "Array to string"
            // warning. `type => string` makes the REST server answer 400
            // before the callback runs — same shape /code-image already uses
            // for its `t` parameter.
            'args'                => [
                'ctx' => [
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
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
 *                                 `ctx` (single-use, 120-second token the
 *                                 under-attack interstitial passes to suppress
 *                                 the code-challenge attachment). A challenge
 *                                 issued for an accepted `ctx` is marked
 *                                 under-attack-only inside its signed
 *                                 parameters and is worthless at a protected
 *                                 form — see Engine::verify().
 * @return WP_REST_Response JSON challenge envelope with `algorithm`, `challenge`,
 *                          `salt`, `signature`, `parameters` and optional
 *                          `codeChallenge.image` URL.
 */
function creationell_captcha_rest_challenge( WP_REST_Request $request ): WP_REST_Response {
    // The under-attack interstitial passes a ctx token so we skip the
    // code-challenge attachment — its widget is display="invisible" and cannot
    // show a code modal.
    //
    // The comment that used to stand here claimed the suppression "cannot be
    // triggered by an arbitrary client, because the token cannot be forged
    // without the HMAC secret". That was wrong, and it is the reason BK-4/CM-4
    // stayed open for so long: not forgeable is not the same as not
    // obtainable. The token is rendered into the 503 page that every anonymous
    // visitor receives — reading it takes one GET, no secret required. What
    // used to make that fatal was the token's shape: one value per five-minute
    // bucket, valid for two buckets, bound to nothing. Anyone could lift it and
    // hand it around for ten minutes.
    //
    // What holds now (see creationell_captcha_underattack_ctx_issue()) is
    // narrower than "bound to the client", and stating it narrowly is the whole
    // point of correcting W5 — the old comment failed because it asserted a
    // property the code did not have:
    //
    //   * single use — the nonce is burned here on the first accepted
    //     presentation, so REPLAY of a spent token is closed;
    //   * 120 s instead of ~10 minutes;
    //   * a MAC over the User-Agent, which is a header the sender chooses.
    //     That is a cheap consistency check, NOT a transfer barrier: whoever
    //     hands a fresh token to another client hands the UA string over with
    //     it, and the check passes.
    //
    // So the ACQUISITION and the PASSING ON of a *fresh* token remain open: one
    // GET of a 503 page yields one code-stage-free challenge, for the fetcher
    // or for whoever he gives it to. What such a challenge is still WORTH is a
    // different question, and that one is answered below and in
    // Engine::verify(): it is marked under-attack-only and no longer redeemable
    // at a protected form (FU-1).
    $ctx                 = (string) $request->get_param( 'ctx' );
    $skip_code_challenge = '' !== $ctx && creationell_captcha_underattack_ctx_check( $ctx );

    $challenge = creationell_captcha_engine()->create_challenge();

    $challenge['codeChallenge'] = null;

    // Both branches below mutate parameters.data, which the initial signature
    // from create_challenge() does not cover any more afterwards. One re-sign
    // site for both, so a new marker can never end up outside the signature.
    $params_mutated = false;

    if ( $skip_code_challenge ) {
        // FU-1 (rest of BK-4/CM-4): this is the one response in which the
        // plugin deliberately omits the image-code stage the configuration
        // asks for, because the interstitial widget cannot display a code
        // modal. Mark the challenge so Engine::verify() can tell it apart and
        // accept it ONLY for the under-attack gate — without the marker the
        // 503 page was a self-service counter for code-stage-free challenges
        // that any protected form accepted.
        //
        // Inside parameters.data, exactly like ccode below, because the re-sign
        // makes the signature cover it: outside the signed parameters the mark
        // would simply be deleted from the payload before submitting it.
        if ( ! isset( $challenge['parameters']['data'] ) || ! is_array( $challenge['parameters']['data'] ) ) {
            $challenge['parameters']['data'] = [];
        }
        $challenge['parameters']['data'][ \Creationell\Captcha\Engine::UA_GATE_PARAM ] = '1';
        $params_mutated = true;
    } elseif ( function_exists( 'creationell_captcha_should_issue_code_challenge' )
        && creationell_captcha_should_issue_code_challenge() ) {
        // Modul 15: attach a code-challenge instruction when triggers match.
        // Embeds the token both in parameters.data.ccode (so it round-trips
        // back to us via the PoW payload) and in the image URL query (so
        // /code-image can render the PNG without state lookup duplication).
        $settings = creationell_captcha_get_settings();
        $expiry   = max( 60, min( 900, (int) ( $settings['code_challenge_expiry'] ?? 300 ) ) );
        $code     = creationell_captcha_generate_code();
        $token    = creationell_captcha_code_token_issue( $code, $expiry );

        // Embed in parameters.data so the ALTCHA-lib signature covers it.
        if ( ! isset( $challenge['parameters']['data'] ) || ! is_array( $challenge['parameters']['data'] ) ) {
            $challenge['parameters']['data'] = [];
        }
        $challenge['parameters']['data']['ccode'] = $token;
        $params_mutated = true;

        $challenge['codeChallenge'] = [
            'image' => rest_url( 'creationell-captcha/v1/code-image' ) . '?t=' . rawurlencode( $token ),
        ];
    }

    if ( $params_mutated ) {
        // Re-sign because we mutated parameters after the initial signing.
        // HMAC algo + format follow `Altcha->hmacHex()` from altcha-lib-php
        // (SHA-256, hex output) over the canonical-JSON form of parameters.
        //
        // With an empty secret nothing is re-signed and the challenge goes out
        // with a signature that no longer matches its parameters. That is not a
        // hole: prepare_payload() rejects every payload fail-closed while the
        // secret is missing, so such an install verifies nothing at all.
        $sig_secret = creationell_captcha_get_hmac_secret();
        if ( '' !== $sig_secret ) {
            $challenge['signature'] = hash_hmac(
                'sha256',
                creationell_captcha_canonical_params_json( $challenge['parameters'] ),
                $sig_secret
            );
        }
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
