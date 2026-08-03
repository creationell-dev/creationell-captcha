<?php
/**
 * Code-Challenge library layer: trigger decision, transient-backed token
 * codec, and random code generator. REST handlers and route registration
 * live at the bottom of this file (added in Task 10).
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Decides whether the current /challenge request should attach a
 * code-challenge instruction. Returns true iff:
 *
 *   1. the master toggle is on, AND
 *   2. PHP-GD is available, AND
 *   3. at least one of the three trigger conditions matches
 *      (under-attack, ratelimit threshold, watch-list).
 */
function creationell_captcha_should_issue_code_challenge(): bool {
    $s = creationell_captcha_get_settings();

    if ( empty( $s['code_challenge_enabled'] ) ) {
        return false;
    }
    if ( ! extension_loaded( 'gd' ) ) {
        return false;
    }

    if ( ! empty( $s['code_challenge_trigger_always'] ) ) {
        return true;
    }

    if ( ! empty( $s['code_challenge_trigger_underattack'] )
        && ! empty( $s['underattack_enabled'] ) ) {
        return true;
    }

    $ip = creationell_captcha_get_client_ip();

    if ( ! empty( $s['code_challenge_trigger_ratelimit'] ) && '' !== $ip ) {
        $current   = creationell_captcha_ratelimit_current_count( $ip );
        $max       = (int) ( $s['ratelimit_max'] ?? 0 );
        $threshold = (int) ( $s['code_challenge_ratelimit_threshold'] ?? 75 );
        if ( $max > 0 && ( $current * 100 / $max ) >= $threshold ) {
            return true;
        }
    }

    if ( ! empty( $s['code_challenge_trigger_watchlist'] ) && '' !== $ip ) {
        $watchlist = (array) ( $s['code_challenge_watchlist'] ?? [] );
        if ( creationell_captcha_ip_in_list( $ip, $watchlist ) ) {
            return true;
        }
    }

    return false;
}

/**
 * Returns the active charset string for the configured option.
 *
 * @param string $charset_key One of: digits / alphanumeric / alphanumeric-no-confusing.
 */
function creationell_captcha_code_charset( string $charset_key ): string {
    $charsets = [
        'digits'                    => '0123456789',
        'alphanumeric'              => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        'alphanumeric-no-confusing' => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
    ];
    return $charsets[ $charset_key ] ?? $charsets['alphanumeric-no-confusing'];
}

/**
 * Generates a fresh random code from the configured charset.
 */
function creationell_captcha_generate_code(): string {
    $s       = creationell_captcha_get_settings();
    $length  = max( 4, min( 8, (int) ( $s['code_challenge_length'] ?? 5 ) ) );
    $charset = creationell_captcha_code_charset(
        (string) ( $s['code_challenge_charset'] ?? 'alphanumeric-no-confusing' )
    );

    $charset_len = strlen( $charset );
    $out         = '';
    for ( $i = 0; $i < $length; $i++ ) {
        $out .= $charset[ random_int( 0, $charset_len - 1 ) ];
    }
    return $out;
}

/**
 * Issues a token backed by a server-side WP transient that stores the
 * expected code for at most $expiry_seconds. Returns the opaque ID that
 * `/code-image` and `/code-verify` use to look the code up again.
 *
 * The code is intentionally NOT encoded into the token itself — a base64
 * round-trip would leak the code to anyone who can read the network
 * response (defeats the OCR-resistant captcha goal). Server state via
 * WP transients is the accepted trade-off.
 *
 * @param string $code            The expected code (already from generator).
 * @param int    $expiry_seconds  Seconds until the token expires.
 */
function creationell_captcha_code_token_issue( string $code, int $expiry_seconds ): string {
    $id = bin2hex( random_bytes( 16 ) );
    set_transient( 'creationell_captcha_cc_' . $id, $code, $expiry_seconds );
    return $id;
}

/**
 * Looks up the code for a token and returns it, or null on:
 *   - malformed token (not 32 hex chars)
 *   - missing transient (expired or unknown)
 *
 * @param string $token   The 32-hex-char ID from `code_token_issue`.
 * @param bool   $consume Delete the transient after successful lookup
 *                       (single-use semantics). The /code-image handler
 *                       passes false; /code-verify passes true ONLY after
 *                       a successful code match so retries on wrong input
 *                       still work.
 */
function creationell_captcha_code_token_verify( string $token, bool $consume = false ): ?string {
    if ( strlen( $token ) !== 32 || ! ctype_xdigit( $token ) ) {
        return null;
    }
    $key  = 'creationell_captcha_cc_' . $token;
    $code = get_transient( $key );
    if ( false === $code || ! is_string( $code ) ) {
        return null;
    }
    if ( $consume ) {
        delete_transient( $key );
    }
    return $code;
}

/**
 * Transient name of the per-token failed-attempt counter (CM-3).
 *
 * @param string $token The 32-hex-char ID from `code_token_issue`.
 */
function creationell_captcha_code_fail_key( string $token ): string {
    return 'creationell_captcha_ccfail_' . $token;
}

/**
 * Records one wrong image-code submission for a token and invalidates the
 * token once its attempt budget is spent.
 *
 * Before this existed, a wrong code was completely free: `/code-verify`
 * returned 401 *before* the consume, nothing was counted, and the REST route
 * is not covered by the default rate-limit scopes (`core`/`forms`). A client
 * could therefore walk a token through the entire code space. The counter
 * lives exactly as long as the token it belongs to, so it cannot be reset by
 * waiting — only by fetching a fresh challenge, which also means a fresh PoW.
 *
 * @param string $token The 32-hex-char ID from `code_token_issue`.
 */
function creationell_captcha_code_token_fail( string $token ): void {
    if ( strlen( $token ) !== 32 || ! ctype_xdigit( $token ) ) {
        return;
    }

    /**
     * Filters how many wrong image-code submissions a single code token
     * survives. Once the budget is spent the token is deleted and the user
     * has to request a new challenge.
     *
     * @since 1.1.0
     * @param int $max Maximum wrong attempts per token. Default 5.
     */
    $max = (int) apply_filters( 'creationell_captcha_code_max_attempts', 5 );
    $max = max( 1, $max );

    $key   = creationell_captcha_code_fail_key( $token );
    $fails = (int) get_transient( $key ) + 1;

    if ( $fails >= $max ) {
        // Budget spent — burn the token itself. Every further attempt now hits
        // the generic "unknown token" path (410) instead of another free guess.
        delete_transient( 'creationell_captcha_cc_' . $token );
        delete_transient( $key );
        return;
    }

    $s      = creationell_captcha_get_settings();
    $expiry = max( 60, min( 900, (int) ( $s['code_challenge_expiry'] ?? 300 ) ) );
    set_transient( $key, $fails, $expiry );
}

/**
 * Handles GET /code-image?t=<token>. Looks up the code from the token
 * (server-side transient), renders the PNG, returns 410 on token failure.
 *
 * Idempotent — the transient is NOT consumed here so the browser may
 * reload the image.
 *
 * @param WP_REST_Request $request The REST request. Required query parameter
 *                                 `t` (opaque server-issued token).
 * @return WP_REST_Response 200 with `image/png` body on success; 410 when the
 *                          token is unknown/expired or PHP-GD is unavailable.
 */
function creationell_captcha_rest_code_image( WP_REST_Request $request ): WP_REST_Response {
    $token = (string) $request->get_param( 't' );
    $code  = creationell_captcha_code_token_verify( $token, false );
    if ( null === $code ) {
        return new WP_REST_Response( null, 410 );
    }

    if ( ! extension_loaded( 'gd' ) ) {
        // The trigger logic gates on GD; defensive fallthrough only.
        return new WP_REST_Response( null, 410 );
    }

    $png = creationell_captcha_render_code_image( $code );

    // Bypass WP_REST_Response's JSON-serialisation: emit PNG body directly
    // and terminate the request before WordPress wraps it.
    if ( ! headers_sent() ) {
        header( 'Content-Type: image/png' );
        header( 'Cache-Control: no-store, max-age=0' );
        http_response_code( 200 );
    }
    echo $png; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped — binary PNG.
    exit;
}

/**
 * Handles POST /code-verify. Two body shapes:
 *
 *   - Code-Challenge mode: { "code": "<user-input>", "payload": "<base64>" }
 *       The widget rendered a code-image because the /challenge response
 *       embedded data.ccode. Token lookup → case-insensitive match →
 *       single-use consume → "code stage passed" marker for this challenge.
 *
 *   - Plain server-verify mode: { "payload": "<base64>" } (no code)
 *       ALTCHA's widget posts here unconditionally whenever verifyUrl is
 *       set (see widget.js logic: `verifyUrl ? _e() : verified()`).
 *       Structural verify only — nothing is consumed, because there is
 *       nothing to protect: the endpoint hands back exactly what it was
 *       given.
 *
 * Neither mode mints a payload any more (CM-5, Wurzel 3.1). The old handler
 * ended in `Engine::issue_signed_payload()`, which made the SERVER solve a
 * fresh PoW (`solveChallenge()`) and returned a ready-to-use payload — one
 * client-side solve was enough to drive an endless loop of server-side key
 * derivations. The response now echoes the SUBMITTED payload back verbatim,
 * so a caller never gains anything it did not already have.
 *
 * @param WP_REST_Request $request The REST request with JSON body
 *                                 `{payload: string, code?: string}`.
 * @return WP_REST_Response 200 on success ({payload, verified: true});
 *                          400 on malformed body; 401 on wrong code;
 *                          410 on missing/expired/unsigned payload or token.
 */
function creationell_captcha_rest_code_verify( WP_REST_Request $request ): WP_REST_Response {
    $body = json_decode( (string) $request->get_body(), true );
    if ( ! is_array( $body )
        || ! isset( $body['payload'] )
        || ! is_string( $body['payload'] ) ) {
        return new WP_REST_Response( [ 'error' => 'invalid_request' ], 400 );
    }
    if ( isset( $body['code'] ) && ! is_string( $body['code'] ) ) {
        return new WP_REST_Response( [ 'error' => 'invalid_request' ], 400 );
    }

    $payload_b64 = $body['payload'];
    $has_code    = isset( $body['code'] );

    // verify_structural() now enforces the challenge signature and the
    // derive-key caps (CM-2/CM-6) before the vendor library derives anything.
    $engine = creationell_captcha_engine();
    if ( ! $engine->verify_structural( $payload_b64 ) ) {
        return new WP_REST_Response( [ 'error' => 'token_expired' ], 410 );
    }

    $decoded = base64_decode( $payload_b64, true );
    if ( false === $decoded ) {
        return new WP_REST_Response( [ 'error' => 'token_expired' ], 410 );
    }
    $data = json_decode( $decoded, true );
    if ( ! is_array( $data ) ) {
        return new WP_REST_Response( [ 'error' => 'token_expired' ], 410 );
    }

    if ( $has_code ) {
        $user_code = trim( $body['code'] );
        $token     = isset( $data['challenge']['parameters']['data']['ccode'] )
            && is_string( $data['challenge']['parameters']['data']['ccode'] )
                ? $data['challenge']['parameters']['data']['ccode']
                : '';

        // Re-read the signature from the payload. verify_structural() already
        // rejected empty ones; this is the value the marker below is bound to.
        $signature = isset( $data['challenge']['signature'] )
            && is_string( $data['challenge']['signature'] )
                ? $data['challenge']['signature']
                : '';
        if ( '' === $signature ) {
            return new WP_REST_Response( [ 'error' => 'token_expired' ], 410 );
        }

        $expected_code = creationell_captcha_code_token_verify( $token, false );
        if ( null === $expected_code ) {
            return new WP_REST_Response( [ 'error' => 'token_expired' ], 410 );
        }

        if ( ! hash_equals( strtoupper( $expected_code ), strtoupper( $user_code ) ) ) {
            // CM-3: a wrong code is no longer free — count it against the
            // token's attempt budget, which burns the token when spent.
            creationell_captcha_code_token_fail( $token );
            return new WP_REST_Response( [ 'error' => 'invalid_code' ], 401 );
        }

        // Correct code. Consume the token (single use) and drop its failure
        // counter, then record that THIS challenge passed the image-code
        // stage. The marker hangs off hash('sha256', challenge.signature),
        // and the signature covers parameters.data.ccode — so the marker
        // cannot be moved to another challenge (CM-8), and a payload whose
        // caller simply omitted the JSON key `code` never gets one (CM-1).
        // Engine::verify() demands the marker for every payload that carries
        // parameters.data.ccode and deletes it when it burns the payload.
        creationell_captcha_code_token_verify( $token, true );
        delete_transient( creationell_captcha_code_fail_key( $token ) );

        // Cross-Strang-Nachtrag (Bündel 3/I1, hier in der
        // Verfügbarkeits-Richtung statt der Sicherheits-Richtung): die
        // Marker-TTL muss an das SIGNIERTE `expiresAt` dieser Challenge
        // gebunden sein, nicht an die `challenge_expiry`-Einstellung zum
        // Verify-Zeitpunkt. `create_challenge()` (class-engine.php) setzt
        // `expiresAt` immer aus dem zum Ausstellungszeitpunkt gültigen Wert;
        // senkt ein Admin `challenge_expiry` danach (z. B. weil derselbe
        // Hilfetext kurze Werte empfiehlt), würde die ALTE Formel die TTL aus
        // dem NEUEN, kürzeren Wert berechnen — kürzer als die Challenge
        // tatsächlich noch gültig ist. Ein Nutzer, der den Bildcode korrekt
        // löst, aber fürs restliche Formular noch etwas braucht, würde beim
        // Submit trotz richtiger Lösung abgewiesen, weil der Marker vorher
        // verfallen ist.
        //
        // `expiresAt` steht in den signierten Challenge-Parametern — die
        // Signatur ist an dieser Stelle bereits geprüft (verify_structural()
        // oben), ein Angreifer kann den Wert also nicht verändern, ohne die
        // Payload unbrauchbar zu machen. Kein zusätzlicher „+1 s"-Ausgleich
        // nötig (anders als beim Sweep in Bündel 3): `verify_structural()`
        // ruft dieselbe Bibliotheksprüfung auf, die eine bereits abgelaufene
        // Challenge (`time() > expiresAt`) schon vorher mit 410 abweist — bei
        // Erreichen dieser Zeile ist `expiresAt - time()` also nie negativ.
        $expires_at = isset( $data['challenge']['parameters']['expiresAt'] )
            && is_int( $data['challenge']['parameters']['expiresAt'] )
                ? $data['challenge']['parameters']['expiresAt']
                : null;

        $marker_ttl = null !== $expires_at
            ? max( 60, $expires_at - time() )
            : max( 60, (int) ( creationell_captcha_get_settings()['challenge_expiry'] ?? 300 ) );
        set_transient( \Creationell\Captcha\Engine::code_pass_key( $signature ), 1, $marker_ttl );
    }

    // Plain mode consumes nothing at all — neither the token nor a replay
    // marker. The old replay consume here only existed because a fresh payload
    // was minted; without minting it had no purpose, and burning the payload
    // here would break the form submit that follows. The single-use guarantee
    // lives entirely in Engine::verify().
    $response = new WP_REST_Response(
        [
            'payload'  => $payload_b64,
            'verified' => true,
        ],
        200
    );
    $response->header( 'Cache-Control', 'no-store, max-age=0' );
    return $response;
}

/**
 * Registers the two code-challenge REST routes. The /challenge handler
 * itself stays in includes/rest.php; Task 11 extends it with the
 * codeChallenge field and the data.ccode embed.
 */
function creationell_captcha_register_code_challenge_routes(): void {
    if ( creationell_captcha_is_disabled() ) {
        return;
    }

    // Wurzel 3.1: both routes exist for one feature only, yet they used to be
    // registered on every install — including the default one, where the image
    // code was never switched on. That is how `/code-verify` (the CM-5
    // amplifier) ended up publicly reachable everywhere. The global kill switch
    // above is explicitly NOT a feature gate; its insufficiency was the root
    // cause, which is why the CI guard demands a settings-based check here.
    $settings = creationell_captcha_get_settings();
    if ( empty( $settings['code_challenge_enabled'] ) ) {
        return;
    }

    register_rest_route(
        'creationell-captcha/v1',
        '/code-image',
        [
            'methods'             => 'GET',
            'callback'            => 'creationell_captcha_rest_code_image',
            'permission_callback' => '__return_true',
            'args'                => [
                't' => [
                    'type'     => 'string',
                    'required' => true,
                ],
            ],
        ]
    );

    register_rest_route(
        'creationell-captcha/v1',
        '/code-verify',
        [
            'methods'             => 'POST',
            'callback'            => 'creationell_captcha_rest_code_verify',
            'permission_callback' => '__return_true',
        ]
    );
}
add_action( 'rest_api_init', 'creationell_captcha_register_code_challenge_routes' );
