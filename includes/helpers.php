<?php
/**
 * Helper functions for CreaCaptcha.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Maps WordPress locales to the matching ALTCHA i18n locale bundle.
 *
 * Keys are values returned by `get_locale()` — including the formal /
 * informal variants WP exposes (`de_DE_formal`, `de_CH_informal`). Values
 * are the exact locale codes used by the vendored ALTCHA bundles under
 * `assets/js/altcha-i18n/<code>.js`. Locales not in the map fall through
 * to the widget's own auto-detection (which itself falls back to English
 * since only the bundles enqueued by this plugin are registered).
 *
 * Extend via the `creationell_captcha_widget_locale_map` filter rather
 * than patching this constant.
 */
const CREATIONELL_CAPTCHA_LOCALE_MAP = [
    // Deutsch
    'de_DE'           => 'de',
    'de_DE_formal'    => 'de',
    'de_AT'           => 'de',
    'de_CH'           => 'de',
    'de_CH_informal'  => 'de',
    // Englisch
    'en_US'           => 'en',
    'en_GB'           => 'en',
    'en_AU'           => 'en',
    'en_CA'           => 'en',
    'en_NZ'           => 'en',
    'en_ZA'           => 'en',
    // Französisch
    'fr_FR'           => 'fr-fr',
    'fr_BE'           => 'fr-fr',
    'fr_LU'           => 'fr-fr',
    'fr_CH'           => 'fr-fr',
    'fr_CA'           => 'fr-ca',
    // Spanisch (Europa)
    'es_ES'           => 'es-es',
    // Spanisch (LatAm — alle nach es-419)
    'es_AR'           => 'es-419',
    'es_CL'           => 'es-419',
    'es_CO'           => 'es-419',
    'es_CR'           => 'es-419',
    'es_DO'           => 'es-419',
    'es_EC'           => 'es-419',
    'es_GT'           => 'es-419',
    'es_HN'           => 'es-419',
    'es_MX'           => 'es-419',
    'es_PA'           => 'es-419',
    'es_PE'           => 'es-419',
    'es_PR'           => 'es-419',
    'es_UY'           => 'es-419',
    'es_VE'           => 'es-419',
    // Portugiesisch
    'pt_PT'           => 'pt-pt',
    'pt_AO'           => 'pt-pt',
    'pt_BR'           => 'pt-br',
    // Italienisch / Niederländisch / Polnisch
    'it_IT'           => 'it',
    'nl_NL'           => 'nl',
    'nl_BE'           => 'nl',
    'pl_PL'           => 'pl',
    // Tschechisch / Slowakisch
    'cs_CZ'           => 'cs',
    'sk_SK'           => 'sk',
    // Nordisch
    'da_DK'           => 'da',
    'sv_SE'           => 'sv',
    'fi'              => 'fi',
    'nb_NO'           => 'nb',
    'nn_NO'           => 'nb',
    // Sonstige EU
    'hu_HU'           => 'hu',
    'ro_RO'           => 'ro',
    'el'              => 'el',
];

/**
 * Resolves the active WordPress locale to a vendored ALTCHA locale code.
 *
 * Returns the locale string (e.g. "de", "fr-fr", "pt-br") if a mapping
 * exists, or null when the WP locale is not in the vendor set — in which
 * case the widget renderer skips both the language attribute and the
 * i18n script enqueue, letting the widget fall through to its own
 * detection (which has only the EN built-in available).
 *
 * Two filters are applied: `creationell_captcha_widget_locale_map` to
 * extend / override the lookup table, and
 * `creationell_captcha_widget_locale` for last-mile overrides after
 * lookup.
 *
 * @since 0.27.0
 * @return string|null Vendored ALTCHA locale code or null.
 */
function creationell_captcha_resolve_widget_locale(): ?string {
    $wp_locale = (string) get_locale();

    /**
     * Filters the WP-locale → ALTCHA-locale lookup map.
     *
     * @since 0.27.0
     * @param array<string, string> $map The default mapping.
     */
    $map = apply_filters(
        'creationell_captcha_widget_locale_map',
        CREATIONELL_CAPTCHA_LOCALE_MAP
    );

    $resolved = is_array( $map ) && isset( $map[ $wp_locale ] ) && is_string( $map[ $wp_locale ] )
        ? $map[ $wp_locale ]
        : null;

    /**
     * Filters the resolved ALTCHA locale code for the widget.
     *
     * Last-mile override after the lookup table has been consulted.
     * Returning null forces the widget into its own auto-detection
     * (no language attribute emitted, no i18n script enqueued).
     *
     * @since 0.27.0
     * @param string|null $resolved  Resolved ALTCHA locale or null.
     * @param string      $wp_locale Active WP locale.
     * @return string|null Overridden locale code, or null to suppress.
     */
    return apply_filters(
        'creationell_captcha_widget_locale',
        $resolved,
        $wp_locale
    );
}

/**
 * Default plugin settings.
 *
 * @return array<string, mixed>
 */
function creationell_captcha_get_default_settings(): array {
    return [
        'algorithm'              => 'pbkdf2',
        'difficulty'             => 'medium',
        'argon2id_memory'        => 32,
        'challenge_expiry'       => 300,
        'widget_display'                => 'standard',
        'widget_floating_anchor'        => '',
        'widget_floating_placement'     => 'auto',
        'widget_floating_offset'        => 12,
        'widget_code_challenge_display' => 'standard',
        'widget_type'                   => 'checkbox',
        'widget_auto_trigger'           => 'none',
        'widget_theme'                  => 'default',
        'widget_hide_branding'          => false,
        'widget_primary_color'          => '',
        'widget_custom_css'             => '',
        'widget_strings_override'       => '',
        'protect_comments'       => true,
        'protect_login'          => true,
        'protect_registration'   => true,
        'protect_password_reset' => true,
        'skip_logged_in'         => true,
        'interceptor_enabled'        => true,
        'interceptor_paths'          => [],
        'interceptor_actions'        => [],
        'interceptor_inject_paths'   => [],
        'interceptor_skip_logged_in' => false,
        'protect_cf7'                => true,
        'protect_forminator'         => true,
        'protect_wpforms'            => true,
        'protect_woocommerce'        => true,
        'protect_wc_checkout'        => true,
        'protect_wc_login'           => true,
        'protect_wc_registration'    => true,
        'protect_wc_lost_password'   => true,
        'firewall_enabled'           => true,
        'firewall_behind_proxy'      => false,
        'firewall_proxy_header'      => 'x-forwarded-for',
        'firewall_trusted_proxies'        => [],
        'firewall_trust_private_ranges'   => false,
        'firewall_trust_cloudflare'       => false,
        'firewall_cloudflare_auto_refresh' => false,
        'firewall_ip_block'          => [],
        'firewall_ip_allow'          => [],
        'firewall_ua_block'          => [],
        'bypass_ua_allow'            => [],
        'bypass_cookies'             => [],
        'ratelimit_enabled'          => false,
        'ratelimit_scope'            => 'core',
        'ratelimit_max'              => 30,
        'ratelimit_window'           => 300,
        'underattack_enabled'        => false,
        'underattack_pass_duration'      => 3600,
        'underattack_logo_url'           => '',
        'underattack_text_title'         => '',
        'underattack_text_heading'       => '',
        'underattack_text_message'       => '',
        'underattack_text_noscript'      => '',
        'underattack_color_background'   => '',
        'underattack_color_text'         => '',
        'underattack_custom_css'         => '',
        'analytics_event_log'        => false,
        'analytics_log_retention'    => 30,
        'log_verified'               => true,
        'log_failed'                 => true,
        'log_firewall'               => true,
        'log_ratelimit'              => true,
        'log_underattack'            => true,
        'log_underattack_passed'     => true,
        'log_challenge'              => false,
        'log_body'                   => false,
        'analytics_anonymize_ip'     => true,
        'obfuscate_emails'           => false,
        'obfuscate_emails_mode'      => 'content',
        'code_challenge_enabled'              => false,
        'code_challenge_trigger_always'       => false,
        'code_challenge_trigger_underattack'  => true,
        'code_challenge_trigger_ratelimit'    => true,
        'code_challenge_trigger_watchlist'    => true,
        'code_challenge_ratelimit_threshold'  => 75,
        'code_challenge_watchlist'            => [],
        'code_challenge_length'               => 5,
        'code_challenge_charset'              => 'alphanumeric-no-confusing',
        'code_challenge_expiry'               => 300,
    ];
}

/**
 * Current plugin settings, merged over the defaults.
 *
 * Memoised for the duration of the request — get_option() itself is cheap
 * thanks to WP's object cache, but the defaults-merge over ~70 keys adds
 * up across the 10+ call sites per request (Interceptor, Firewall, Rate-
 * Limiter, Under-Attack, every form integration). The cache is invalidated
 * automatically when the option is added, updated or deleted.
 *
 * @param bool $force_refresh Re-read from the DB even if a cached copy exists.
 *                            Used by the invalidation hook.
 * @return array<string, mixed>
 */
function creationell_captcha_get_settings( bool $force_refresh = false ): array {
    static $cache = null;

    if ( $force_refresh ) {
        $cache = null;
    }

    if ( null !== $cache ) {
        return $cache;
    }

    $stored = get_option( 'creationell_captcha_settings', [] );
    if ( ! is_array( $stored ) ) {
        $stored = [];
    }

    $cache = array_merge( creationell_captcha_get_default_settings(), $stored );
    return $cache;
}

/**
 * Drops the in-request settings cache. Wired to the option-change hooks below
 * so callers that read settings after an update see the fresh value.
 */
function creationell_captcha_invalidate_settings_cache(): void {
    creationell_captcha_get_settings( true );
}
add_action( 'update_option_creationell_captcha_settings', 'creationell_captcha_invalidate_settings_cache' );
add_action( 'add_option_creationell_captcha_settings', 'creationell_captcha_invalidate_settings_cache' );
add_action( 'delete_option_creationell_captcha_settings', 'creationell_captcha_invalidate_settings_cache' );

/**
 * Whether the captcha is globally disabled via the wp-config constant.
 */
function creationell_captcha_is_disabled(): bool {
    return defined( 'CREATIONELL_CAPTCHA_DISABLE' ) && CREATIONELL_CAPTCHA_DISABLE;
}

/**
 * Whether ext-sodium (required for Argon2id) is available.
 */
function creationell_captcha_sodium_available(): bool {
    return function_exists( 'sodium_crypto_pwhash' );
}

/**
 * Generates both HMAC secrets and persists them (non-autoloaded).
 *
 * @return array{signature: string, key_signature: string}
 */
function creationell_captcha_generate_secrets(): array {
    $secrets = [
        'signature'     => bin2hex( random_bytes( 32 ) ),
        'key_signature' => bin2hex( random_bytes( 32 ) ),
    ];
    update_option( 'creationell_captcha_secrets', $secrets, false );

    return $secrets;
}

/**
 * Returns a stored HMAC secret, generating + persisting it on first use.
 *
 * @param string $which Either 'signature' or 'key_signature'.
 */
function creationell_captcha_get_secret( string $which ): string {
    $secrets = get_option( 'creationell_captcha_secrets', [] );

    if ( ! is_array( $secrets ) || empty( $secrets['signature'] ) || empty( $secrets['key_signature'] ) ) {
        $secrets = creationell_captcha_generate_secrets();
    }

    return (string) ( $secrets[ $which ] ?? '' );
}

/**
 * The HMAC signature secret (signs each challenge).
 *
 * A wp-config constant takes precedence over the stored option.
 */
function creationell_captcha_get_hmac_secret(): string {
    if ( defined( 'CREATIONELL_CAPTCHA_HMAC_SECRET' )
        && is_string( CREATIONELL_CAPTCHA_HMAC_SECRET )
        && '' !== CREATIONELL_CAPTCHA_HMAC_SECRET
    ) {
        return CREATIONELL_CAPTCHA_HMAC_SECRET;
    }

    return creationell_captcha_get_secret( 'signature' );
}

/**
 * The HMAC key-signature secret (enables the fast verification path).
 *
 * A wp-config constant takes precedence over the stored option.
 */
function creationell_captcha_get_hmac_key_secret(): string {
    if ( defined( 'CREATIONELL_CAPTCHA_HMAC_KEY_SECRET' )
        && is_string( CREATIONELL_CAPTCHA_HMAC_KEY_SECRET )
        && '' !== CREATIONELL_CAPTCHA_HMAC_KEY_SECRET
    ) {
        return CREATIONELL_CAPTCHA_HMAC_KEY_SECRET;
    }

    return creationell_captcha_get_secret( 'key_signature' );
}

/**
 * Purpose label of the under-attack pass-cookie key.
 */
const CREATIONELL_CAPTCHA_PURPOSE_UA_PASS = 'underattack-pass';

/**
 * Purpose label of the under-attack code-challenge suppression token (`ctx`).
 */
const CREATIONELL_CAPTCHA_PURPOSE_UA_CTX = 'underattack-ctx';

/**
 * Lifetime (seconds) of a `ctx` suppression token. The interstitial widget
 * fetches the challenge on load, i.e. within seconds of the 503 being
 * rendered; two minutes is generous for that and replaces the ~10 minutes the
 * old 5-minute-bucket pair accepted (BK-4).
 */
const CREATIONELL_CAPTCHA_UA_CTX_TTL = 120;

/**
 * Derives a purpose-bound HMAC key from the plugin's base signature secret.
 *
 * Wurzel 3.5: the challenge signature, the under-attack pass cookie and the
 * `ctx` suppression token were all MACs under the SAME key. Cross-purpose use
 * was only prevented by the differing message layout — a fragile property that
 * breaks silently as soon as one token family changes its format. HKDF-style
 * expansion with a purpose label makes the separation structural: a MAC minted
 * for one purpose verifies under no other key.
 *
 * The base secret stays exactly where it is (`CREATIONELL_CAPTCHA_HMAC_SECRET`
 * / the stored option) — the derivation sits in front of it, so the ALTCHA
 * library keeps signing challenges with the unchanged base key.
 *
 * @since 1.1.0
 * @param string $purpose Stable purpose label, e.g. `underattack-pass`.
 * @return string 64-char hex key, or '' when no base secret is available
 *                (callers must fail closed on '').
 */
function creationell_captcha_derive_hmac_key( string $purpose ): string {
    $base = creationell_captcha_get_hmac_secret();
    if ( '' === $base || '' === $purpose ) {
        return '';
    }

    return hash_hmac( 'sha256', 'creationell-captcha/v1/' . $purpose, $base );
}

/**
 * The request's User-Agent, capped at 256 bytes. MAC input for the
 * under-attack tokens — never rendered, never stored.
 *
 * @since 1.1.0
 */
function creationell_captcha_client_ua(): string {
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- MAC input only, never echoed.
    $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';

    return strlen( $ua ) > 256 ? substr( $ua, 0, 256 ) : $ua;
}

/**
 * The fingerprint the under-attack pass cookie is bound to (BK-3).
 *
 * Two components, neither of which travels inside the cookie. Only one of them
 * is load-bearing, and it is worth naming which: the NETWORK is what a
 * recipient cannot bring along, because it is where his packets come from. The
 * User-Agent he can bring along — he sends it himself, and whoever passes the
 * cookie on passes the UA string on with it. So the UA is a cheap extra, the
 * network is the half that actually refuses a transferred cookie.
 *
 *  - the client NETWORK (IPv4 /24, IPv6 /48 — the same reduction the analytics
 *    anonymiser applies), resolved through `creationell_captcha_get_client_ip()`
 *    so a forwarded header only counts behind a trusted proxy (BK-7/BK-8) and
 *    never straight off an attacker-set header;
 *  - the User-Agent.
 *
 * Trade-off, deliberately made here and not at the two call sites: the
 * User-Agent alone is weak (whoever passes the cookie on passes the UA string
 * on with it), the full address breaks on every mobile hand-over. The network
 * is the middle ground — it survives the address churn inside one access
 * network (CGNAT pool, IPv6 privacy extensions) and still refuses a cookie
 * that travelled to a different one. A false negative costs exactly one extra
 * proof-of-work: the visitor sees the interstitial again, solves it and gets a
 * cookie bound to the new network. No lock-out, no loop.
 *
 * @since 1.1.0
 * @return string Binding string; '' disables the binding entirely.
 */
function creationell_captcha_underattack_pass_binding(): string {
    /**
     * Filters the visitor fingerprint the under-attack pass cookie is bound to.
     *
     * Return `''` to switch the binding off completely — the cookie is then a
     * pure bearer token again (the pre-1.1.0 behaviour) and can be handed to
     * any number of clients until it expires. Sites whose visitors legitimately
     * change network mid-session (carrier hand-over on long pass durations) can
     * also narrow it down, e.g. to the User-Agent only.
     *
     * The value is MAC input only; it is never rendered and never stored.
     *
     * @since 1.1.0
     * @param string $binding Default binding: client network + User-Agent.
     */
    return (string) apply_filters(
        'creationell_captcha_underattack_pass_binding',
        creationell_captcha_anonymize_ip( creationell_captcha_get_client_ip() )
            . "\n" . creationell_captcha_client_ua()
    );
}

/**
 * Mints an under-attack pass token for the current visitor.
 *
 * @since 1.1.0
 * @param int $expiry Absolute Unix timestamp the pass runs out at.
 * @return string `<expiry>.<mac>` token, or '' when no key could be derived.
 */
function creationell_captcha_underattack_pass_issue( int $expiry ): string {
    $key = creationell_captcha_derive_hmac_key( CREATIONELL_CAPTCHA_PURPOSE_UA_PASS );
    if ( '' === $key ) {
        return '';
    }

    return $expiry . '.' . hash_hmac(
        'sha256',
        $expiry . '|' . creationell_captcha_underattack_pass_binding(),
        $key
    );
}

/**
 * Verifies an under-attack pass token against the CURRENT visitor.
 *
 * BK-3: before 1.1.0 the MAC covered the expiry timestamp and nothing else, so
 * one solved interstitial produced a bearer token that worked from any client,
 * any address, for up to `underattack_pass_duration` (86400 s). The MAC now
 * covers the visitor binding as well, which is not part of the cookie value.
 *
 * @since 1.1.0
 * @param string $cookie Raw cookie value.
 */
function creationell_captcha_underattack_pass_check( string $cookie ): bool {
    $parts = explode( '.', $cookie, 2 );
    if ( 2 !== count( $parts ) ) {
        return false;
    }
    [ $expiry_raw, $mac ] = $parts;

    if ( ! ctype_digit( $expiry_raw ) || (int) $expiry_raw <= time() ) {
        return false;
    }

    $key = creationell_captcha_derive_hmac_key( CREATIONELL_CAPTCHA_PURPOSE_UA_PASS );
    if ( '' === $key ) {
        // No key, no decision we could trust — fail closed (interstitial stays).
        return false;
    }

    $expected = hash_hmac(
        'sha256',
        $expiry_raw . '|' . creationell_captcha_underattack_pass_binding(),
        $key
    );

    if ( hash_equals( $expected, $mac ) ) {
        return true;
    }

    // Also the path every pre-1.1.0 cookie takes: the old MAC covered only the
    // timestamp, so it cannot match. Those visitors see the interstitial once
    // more and get a bound cookie — no lock-out, no loop.
    creationell_captcha_log( 'under-attack pass: token rejected (binding or MAC mismatch)' );

    return false;
}

/**
 * Mints a single-use `ctx` suppression token for one interstitial rendering.
 *
 * BK-4/CM-4/W5: the old token was `HMAC(secret, 'ua-ctx|' . floor(time()/300))`
 * — identical for every visitor inside a five-minute bucket and accepted for
 * the current AND the previous bucket, i.e. up to ten minutes. It was handed
 * to every anonymous 503 visitor inside the HTML. Unforgeable, yes — but
 * trivially *obtainable*, transferable and replayable.
 *
 * The replacement carries a random nonce (so every rendering gets its own
 * token), an explicit expiry and a MAC over nonce, expiry and the visitor's
 * User-Agent. It is burned on first use in `…_ctx_check()`.
 *
 * What this closes, precisely — and what it does NOT:
 *
 *  - REPLAY is closed. The nonce is burned on first use, so one token buys at
 *    most one suppressed challenge (1.0.2: unlimited inside its bucket pair).
 *  - The accepted WINDOW shrinks from ~10 minutes to 120 seconds.
 *  - ACQUISITION stays open. One GET of a 503 page still yields one fresh
 *    token, i.e. one code-stage-free challenge. Closing that needs the issued
 *    challenge itself to be marked under-attack-only and checked on redemption
 *    inside `Engine::verify()` — outside this file (R1 in the task report).
 *  - HANDING A FRESH TOKEN ON stays open as well. The MAC covers the
 *    User-Agent, but the User-Agent is a value the RECIPIENT sends himself:
 *    whoever passes the token to a bot passes the UA string along with it. The
 *    binding costs an attacker one header, no more. It is kept because it is
 *    free and it does stop a token that leaked WITHOUT its UA (log excerpt,
 *    referrer, a URL shared out of band). It is not a transfer barrier, and no
 *    comment on this token may claim that it is — W5 was exactly that kind of
 *    claim, made about exactly this token.
 *
 * WHAT SINGLE USE COSTS (m7): the token is spent by the FIRST challenge fetch
 * of the interstitial that carried it. If the very same 503 HTML reaches a
 * browser a second time — restored from the back/forward cache, or replayed by
 * a full-page cache or CDN that ignores the response headers — the widget
 * fetches again with a token that is already burned. `/challenge` then answers
 * without the suppression, and with `code_challenge_enabled` on that means the
 * INVISIBLE interstitial widget receives an image code it cannot display: that
 * visitor never passes the gate at all. The interstitial itself asks not to be
 * stored (`nocache_headers()` sends `no-store, private`, measured against the
 * WordPress 7.0.2 of the test instance), so this needs a cache that disregards
 * that — but such caches exist, and "under attack" is exactly when an operator
 * puts one in front of the site. Making that visible is a `doctor` job
 * ("under-attack mode on and a full-page cache detected"); it cannot be fixed
 * from the token side without giving up the single use that closed BK-4.
 *
 * Why no client-network binding here, unlike the pass cookie: it would not
 * reduce what an attacker can do — every bot can fetch its own 503 page, so
 * handing a token around buys nothing over simply acquiring one — while a
 * false negative here is a dead end instead of a retry. A rejected pass cookie
 * costs one extra proof-of-work; a rejected `ctx` gets the interstitial's
 * invisible widget an image code it cannot display, and that visitor never
 * passes the gate at all. On top of that the address is not even constant
 * across the two requests of ONE visitor: the XHR that fetches the challenge
 * can leave through a different address than the page view that carried the
 * token (dual-stack clients pick the family per connection, egress pools
 * rotate well beyond a /24).
 *
 * @since 1.1.0
 * @return string `<nonce>.<expiry>.<mac>`, or '' when no key could be derived.
 */
function creationell_captcha_underattack_ctx_issue(): string {
    $key = creationell_captcha_derive_hmac_key( CREATIONELL_CAPTCHA_PURPOSE_UA_CTX );
    if ( '' === $key ) {
        return '';
    }

    $nonce  = bin2hex( random_bytes( 16 ) );
    $expiry = time() + CREATIONELL_CAPTCHA_UA_CTX_TTL;

    return $nonce . '.' . $expiry . '.' . hash_hmac(
        'sha256',
        $nonce . '|' . $expiry . '|' . creationell_captcha_client_ua(),
        $key
    );
}

/**
 * Verifies a `ctx` suppression token and consumes it.
 *
 * Returns true at most ONCE per token: the nonce is recorded for the rest of
 * the token's lifetime, every later presentation of the same token fails.
 *
 * @since 1.1.0
 * @param string $token Raw `ctx` query value.
 */
function creationell_captcha_underattack_ctx_check( string $token ): bool {
    $parts = explode( '.', $token, 3 );
    if ( 3 !== count( $parts ) ) {
        return false;
    }
    [ $nonce, $expiry_raw, $mac ] = $parts;

    if ( 32 !== strlen( $nonce ) || ! ctype_xdigit( $nonce ) || ! ctype_digit( $expiry_raw ) ) {
        return false;
    }

    $now    = time();
    $expiry = (int) $expiry_raw;
    // Upper bound as well as lower: a token may never claim a longer life than
    // this server is willing to mint.
    if ( $expiry <= $now || $expiry > $now + CREATIONELL_CAPTCHA_UA_CTX_TTL ) {
        return false;
    }

    $key = creationell_captcha_derive_hmac_key( CREATIONELL_CAPTCHA_PURPOSE_UA_CTX );
    if ( '' === $key ) {
        return false;
    }

    $expected = hash_hmac(
        'sha256',
        $nonce . '|' . $expiry . '|' . creationell_captcha_client_ua(),
        $key
    );
    if ( ! hash_equals( $expected, $mac ) ) {
        return false;
    }

    // Single use. The marker outlives the token by a minute so a replay right
    // at the expiry edge still finds it.
    //
    // Deliberately a plain get/set pair and not the atomic INSERT-IGNORE claim
    // the replay marker in class-engine.php uses (CM-9): two exactly parallel
    // presentations of the same token could both win the race and get one
    // suppressed challenge each. That is worth nothing to an attacker — a
    // second 503 request hands out a second token anyway. The atomic path
    // costs an options row plus a cron sweep per interstitial and would be
    // paid precisely while the site is under attack.
    $marker = 'creationell_captcha_uactx_' . $nonce;
    if ( false !== get_transient( $marker ) ) {
        creationell_captcha_log( 'under-attack ctx: token already spent' );
        return false;
    }
    set_transient( $marker, 1, ( $expiry - $now ) + 60 );

    return true;
}

/**
 * Shared captcha engine instance.
 */
function creationell_captcha_engine(): \Creationell\Captcha\Engine {
    static $engine = null;

    if ( null === $engine ) {
        $engine = new \Creationell\Captcha\Engine();
    }

    return $engine;
}

/**
 * Write a message to the debug log when CREATIONELL_CAPTCHA_DEBUG is active.
 *
 * W1-13: Steuerzeichen werden entfernt, BEVOR die Zeile geschrieben wird —
 * dieselbe Reduktion, die `Analytics::current_path()` für die Log-Tabelle
 * vornimmt. Mehrere Meldungen tragen vom Absender bestimmte Bestandteile in
 * die Zeile, allen voran der Interceptor („interceptor blocked POST to " plus
 * dem EINMAL dekodierten Pfad, class-interceptor.php): ein anonymer
 * `POST /kontakt%0A` auf einen per `/kontakt*` geschützten Pfad wird von
 * WordPress geroutet (`WP::parse_request()` trimmt, und die Rewrite-Regel
 * `^kontakt/?$` trifft dank `$` vor dem Zeilenumbruch), der Interceptor
 * blockiert — und die Logzeile enthielt einen echten Zeilenumbruch. Damit
 * bestimmte der Absender, wo eine Zeile im PHP-Fehlerlog endet, und konnte
 * eine zweite, frei gewählte anhängen.
 *
 * Bewusst hier und nicht an der einen Aufrufstelle: dies ist die Senke, durch
 * die JEDE Meldung des Plugins geht, und keine von ihnen enthält eine
 * beabsichtigte mehrzeilige Ausgabe (nachgezählt über alle Aufrufer). Eine
 * Reparatur je Aufrufstelle wäre dieselbe Zeile mehrfach — und die nächste
 * neue Meldung hätte sie wieder nicht.
 *
 * @param string $message Message to log.
 */
function creationell_captcha_log( string $message ): void {
    if ( defined( 'CREATIONELL_CAPTCHA_DEBUG' ) && CREATIONELL_CAPTCHA_DEBUG ) {
        error_log( '[creationell-captcha] ' . (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $message ) );
    }
}

/**
 * Canonicalises an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) into its plain
 * IPv4 spelling. Every other value — including anything that is not an IP at
 * all — is handed back unchanged.
 *
 * WHY (audit module 27, finding I2)
 * ---------------------------------
 * On every server whose PHP sees the peer address in IPv4-mapped notation
 * (nginx `listen [::]:443 ipv6only=off`, Apache on an IPv6 socket, plenty of
 * container and proxy setups) `REMOTE_ADDR` reads `::ffff:203.0.113.7` for an
 * ordinary IPv4 client. That string passes `FILTER_VALIDATE_IP` — it is a
 * perfectly valid IPv6 address — so nothing ever complained, but:
 *
 *   - `ip_in_cidr()` refuses a family change (4 vs. 16 bytes, correctly so),
 *     and `ip_in_list()` otherwise compares plain strings;
 *   - so `firewall_ip_block`, `firewall_ip_allow`, `firewall_trusted_proxies`
 *     and `code_challenge_watchlist` matched NOTHING for those clients — the
 *     IP firewall was silently inert, and the admin who allow-listed his own
 *     address locked himself out anyway;
 *   - `anonymize_ip()` reduced all of them to `::`, which took the network
 *     half out of the BK-3 under-attack pass binding and left a pure bearer
 *     token behind.
 *
 * The check runs on the binary form rather than on the string, so the rarer
 * spellings (`::FFFF:cb00:7107`, `0:0:0:0:0:ffff:203.0.113.7`) are caught as
 * well. `::` and `::ffff:0:0:0` are NOT mapped addresses and stay untouched.
 *
 * @since 1.1.0
 *
 * @param string $ip Candidate address.
 * @return string Plain IPv4 spelling for mapped addresses, else the input.
 */
function creationell_captcha_normalize_ip( string $ip ): string {
    if ( '' === $ip || ! str_contains( $ip, ':' ) ) {
        return $ip;
    }

    $bin = @inet_pton( $ip );
    if ( false === $bin || 16 !== strlen( $bin ) ) {
        return $ip;
    }

    // RFC 4291 §2.5.5.2: 80 zero bits, 16 one bits, then the IPv4 address.
    if ( "\0\0\0\0\0\0\0\0\0\0\xff\xff" !== substr( $bin, 0, 12 ) ) {
        return $ip;
    }

    $plain = @inet_ntop( substr( $bin, 12 ) );

    return is_string( $plain ) ? $plain : $ip;
}

/**
 * Resolves the client IP address.
 *
 * Returns the validated REMOTE_ADDR by default. When the `firewall_behind_proxy`
 * setting is on, the configured forwarded header is used instead — falling back
 * to REMOTE_ADDR if it yields no valid IP.
 *
 * This is the single ingress for client addresses: every list check, the
 * rate-limit bucket key, the pass binding and the event log take their value
 * from here. Canonicalising IPv4-mapped addresses therefore happens HERE and
 * not at each of those places (I2).
 *
 * WHAT THE FALLBACK COSTS (m3 / W2-3) — say it here, because it is not obvious
 * at the call sites: every `return $remote` below hands the PROXY's address to
 * everything downstream. That is the safe direction (BK-8: an entry we cannot
 * classify must never let a forged one to its left win), but it is not a free
 * one. If a fallback fires on EVERY request — an upstream that appends
 * `unknown` or an obfuscated identifier per RFC 7239, an Azure-style
 * `ip:port` hop, a `firewall_proxy_header` naming a header this installation
 * does not actually receive — then all visitors share one address:
 *
 *  - the rate limiter counts the whole site into one bucket and locks everyone
 *    out at the threshold;
 *  - `firewall_ip_block` and `code_challenge_watchlist` hit all or nothing;
 *  - and if the proxy address happens to sit in `firewall_ip_allow`, every
 *    visitor is bypassed.
 *
 * Each fallback therefore names itself through `creationell_captcha_log()`.
 * That is only visible with `CREATIONELL_CAPTCHA_DEBUG`; making it visible
 * without the debug switch belongs to the settings help text and to
 * `wp creacaptcha doctor`, not here.
 */
function creationell_captcha_get_client_ip(): string {
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated via FILTER_VALIDATE_IP.
    $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
    $remote = filter_var( $remote, FILTER_VALIDATE_IP ) ? creationell_captcha_normalize_ip( $remote ) : '';

    $settings = creationell_captcha_get_settings();
    if ( empty( $settings['firewall_behind_proxy'] ) ) {
        return $remote;
    }

    $header_map = [
        'x-forwarded-for'  => 'HTTP_X_FORWARDED_FOR',
        'x-real-ip'        => 'HTTP_X_REAL_IP',
        'cf-connecting-ip' => 'HTTP_CF_CONNECTING_IP',
        'true-client-ip'   => 'HTTP_TRUE_CLIENT_IP',
    ];
    $choice = (string) ( $settings['firewall_proxy_header'] ?? 'x-forwarded-for' );

    /*
     * m2: the fallback used to be applied to the SERVER KEY only
     * (`$header_map[ $choice ] ?? 'HTTP_X_FORWARDED_FOR'`), so an unknown value
     * read X-Forwarded-For but kept the single-value splitting below —
     * `'x-forwarded-for' === $choice` stayed false. A real chain
     * ("198.51.100.23, 203.0.113.10") then arrived as ONE entry, failed
     * FILTER_VALIDATE_IP, broke the walk, and get_client_ip() returned
     * REMOTE_ADDR on every request: the proxy mode was off and nothing said so.
     * Since REMOTE_ADDR is the trusted proxy in that branch, every visitor
     * collapsed onto one address — the rate limiter counts them together, and
     * if that address sits in firewall_ip_allow it is a bypass for the whole
     * site.
     *
     * Correcting the CHOICE instead of the key keeps header and splitting in
     * step. Only reachable by writing the option directly (`wp option patch`, a
     * restored backup, a foreign update_option()); the settings page offers the
     * four known values only.
     */
    if ( ! isset( $header_map[ $choice ] ) ) {
        creationell_captcha_log(
            'client-ip: unknown firewall_proxy_header "' . $choice . '" — falling back to x-forwarded-for'
        );
        $choice = 'x-forwarded-for';
    }
    $server_key = $header_map[ $choice ];

    if ( '' === $remote ) {
        // No REMOTE_ADDR at all: cannot evaluate trust → safest is to bail
        // and let downstream features treat the request as "unknown IP".
        return '';
    }

    if ( ! creationell_captcha_is_trusted_proxy( $remote ) ) {
        creationell_captcha_log( 'client-ip: ' . $remote . ' (fallback: remote not trusted)' );
        return $remote;
    }

    if ( ! isset( $_SERVER[ $server_key ] ) ) {
        return $remote;
    }

    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated below.
    $raw = (string) wp_unslash( $_SERVER[ $server_key ] );

    // BK-7: the single-value headers (x-real-ip, cf-connecting-ip,
    // true-client-ip) used to be taken at face value the moment the peer was
    // trusted — they never saw the per-entry trust check the XFF chain got.
    // Both shapes now run through the SAME walk below; the only difference is
    // how many hops the header can carry.
    $entries = ( 'x-forwarded-for' === $choice )
        ? array_map( 'trim', explode( ',', $raw ) )
        : [ trim( $raw ) ];

    // BK-8: walk right to left and stop at the FIRST hop that is not one of
    // our own proxies — that hop is what our infrastructure actually saw, and
    // it is the genuine client. Everything further left was written by
    // somebody we do not trust and is freely forgeable, so it must never win.
    // The old loop `continue`d past entries it could not classify, which let a
    // forged entry sitting left of an unparsable one become the client IP.
    for ( $i = count( $entries ) - 1; $i >= 0; $i-- ) {
        $entry = $entries[ $i ];

        if ( '' === $entry || false === filter_var( $entry, FILTER_VALIDATE_IP ) ) {
            // Chain broken: we cannot tell who appended what to the left of a
            // hop we cannot even parse. Fall back to the one address the TCP
            // stack vouched for.
            creationell_captcha_log( 'client-ip: ' . $remote . ' (fallback: unparsable hop in ' . $choice . ')' );
            return $remote;
        }

        // I2: a hop may arrive IPv4-mapped just like REMOTE_ADDR can — and a
        // mapped hop would miss the trusted-proxy list below, which would make
        // our OWN proxy look like the client.
        $entry = creationell_captcha_normalize_ip( $entry );

        if ( creationell_captcha_is_trusted_proxy( $entry ) ) {
            continue;
        }

        creationell_captcha_log( 'client-ip: ' . $entry . ' (via ' . $choice . ', trusted remote ' . $remote . ')' );
        return $entry;
    }

    // Every hop was one of our own proxies (or the header was empty) — no
    // client address in there, bail to REMOTE_ADDR.
    return $remote;
}

/**
 * Whether an IP matches any entry in a list of IPs or CIDR ranges.
 *
 * This is the choke point all four address lists run through — blocklist,
 * allowlist, trusted proxies and the code-challenge watchlist — which is why
 * the IPv4-mapped canonicalisation is applied here and not four times over.
 *
 * Admin-typed entries are canonicalised as well, so an installation that spelled
 * an entry `::ffff:203.0.113.7` (the only spelling that worked on an affected
 * server before this release) keeps matching. CIDR entries are deliberately NOT
 * rewritten: a mapped range like `::ffff:0:0/96` would widen to "every IPv4
 * address", and silently widening a TRUSTED-PROXY range is the one direction
 * this plugin must never take (LK-13/AF-5). A CIDR written in mapped notation
 * therefore stops matching — see the note on ip_in_cidr().
 *
 * @param string $ip   The client IP.
 * @param mixed  $list A list of IPs / CIDR ranges (non-arrays are ignored).
 */
function creationell_captcha_ip_in_list( string $ip, $list ): bool {
    if ( '' === $ip || ! is_array( $list ) ) {
        return false;
    }

    $ip = creationell_captcha_normalize_ip( $ip );

    foreach ( $list as $entry ) {
        // A stored list is an ordinary option: a restored backup or a
        // `wp option patch` can put a nested array or an object in there. The
        // (string) cast below would warn on the first and raise an uncatchable
        // Error on the second, on every request that reaches this list.
        if ( ! is_scalar( $entry ) ) {
            continue;
        }
        $entry = trim( (string) $entry );
        if ( '' === $entry ) {
            continue;
        }
        if ( str_contains( $entry, '/' ) ) {
            if ( creationell_captcha_ip_in_cidr( $ip, $entry ) ) {
                return true;
            }
        } elseif ( 0 === strcasecmp( $ip, creationell_captcha_normalize_ip( $entry ) ) ) {
            return true;
        }
    }

    return false;
}

/**
 * Whether an IP falls within a CIDR range. Supports IPv4 and IPv6.
 *
 * The subject is canonicalised (I2); the RANGE is taken as written. A range
 * spelled in IPv4-mapped notation (`::ffff:203.0.113.0/120`) consequently no
 * longer matches an IPv4 client — deliberately, because converting it would
 * mean rewriting prefix lengths, and a wrong prefix in a trusted-proxy list is
 * the failure mode this plugin has already had to close twice.
 *
 * @param string $ip   The client IP.
 * @param string $cidr A CIDR range, e.g. "203.0.113.0/24".
 */
function creationell_captcha_ip_in_cidr( string $ip, string $cidr ): bool {
    [ $subnet, $bits ] = array_pad( explode( '/', $cidr, 2 ), 2, '' );

    $ip_bin     = @inet_pton( creationell_captcha_normalize_ip( $ip ) );
    $subnet_bin = @inet_pton( $subnet );
    if ( false === $ip_bin || false === $subnet_bin ) {
        return false;
    }
    // The IP and the subnet must be the same family (4 or 16 bytes).
    if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
        return false;
    }

    // A missing or non-numeric prefix length (e.g. "10.0.0.0/") is invalid and
    // must never collapse to a match-everything /0.
    if ( ! ctype_digit( $bits ) ) {
        return false;
    }
    $bits = (int) $bits;
    $max  = strlen( $ip_bin ) * 8;
    if ( $bits > $max ) {
        return false;
    }

    $whole_bytes = intdiv( $bits, 8 );
    $rem_bits    = $bits % 8;

    if ( $whole_bytes > 0 && 0 !== substr_compare( $ip_bin, $subnet_bin, 0, $whole_bytes ) ) {
        return false;
    }
    if ( 0 === $rem_bits ) {
        return true;
    }

    $mask = chr( ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF );

    return ( $ip_bin[ $whole_bytes ] & $mask ) === ( $subnet_bin[ $whole_bytes ] & $mask );
}

/**
 * Whether a string is a valid IP address or CIDR range (IPv4 or IPv6).
 *
 * Prefix length 0 (`0.0.0.0/0`, `::/0`) is refused: it is valid CIDR notation
 * but matches every address, so as a firewall-allow, trusted-proxy or
 * blocklist entry it silently disables the very list it is in (AF-5). An admin
 * who really wants to cover the whole address space can still spell it out as
 * two halves (`0.0.0.0/1` + `128.0.0.0/1`) and thereby say so on purpose.
 *
 * This is an input guard only — it decides what may be STORED. Values already
 * in the database keep working; reporting on those is the fail-safe migration's
 * job, not this function's.
 *
 * @param string $entry The candidate string.
 */
function creationell_captcha_is_valid_ip_or_cidr( string $entry ): bool {
    $entry = trim( $entry );
    if ( '' === $entry ) {
        return false;
    }

    if ( ! str_contains( $entry, '/' ) ) {
        return false !== filter_var( $entry, FILTER_VALIDATE_IP );
    }

    [ $subnet, $bits ] = array_pad( explode( '/', $entry, 2 ), 2, '' );

    $subnet_bin = @inet_pton( $subnet );
    if ( false === $subnet_bin ) {
        return false;
    }
    if ( ! ctype_digit( $bits ) ) {
        return false;
    }
    $max = strlen( $subnet_bin ) * 8;
    return (int) $bits >= 1 && (int) $bits <= $max;
}

/**
 * Whether a subject matches any of the given wildcard patterns (case-insensitive).
 *
 * The pattern alphabet is the same as the firewall UA-blocklist: `*` is the
 * single wildcard, everything else is matched literally.
 *
 * The two edge cases used to be decided implicitly, and the decision was wrong
 * for one of the two call sites (BK-9). Both are now the caller's to make:
 *
 *  - `$empty_subject_matches` — a missing header is not "the empty string", it
 *    is no information at all. For a blocklist "no match" is the safe answer,
 *    for an allowlist it is too, but the two reach it for opposite reasons, so
 *    neither may inherit it silently.
 *  - `$allow_catch_all` — a pattern of nothing but `*` matches every non-empty
 *    subject. Harmless in a blocklist, a total shutdown of the protection in
 *    an allowlist. Pass false there and such a pattern is skipped.
 *
 * WHERE `$allow_catch_all` STOPS — READ THIS BEFORE TRUSTING IT
 * ------------------------------------------------------------
 * The guard is SYNTACTIC and nothing else: it drops a pattern when
 * `trim( $pattern, '*' )` leaves nothing behind, i.e. `*`, `**`, `***`. It does
 * NOT drop a pattern that merely happens to match everything in practice.
 * Measured against the production path: star-slash-star (written out because the
 * literal form would close this comment block) passes this guard and matches
 * every realistic User-Agent — every one of them carries a slash. Same for
 * star-dot-star. `false` here therefore means "no bare star", not "no
 * catch-all".
 *
 * That boundary is deliberate. "Matches every real subject" is not a decidable
 * property of a pattern; the nearest thing to it is the five-probe criterion in
 * `creationell_captcha_hardening_matches_every_user_agent()`, and a heuristic
 * has no business deciding a single request — least of all one that would run
 * on every request, for every stored pattern. Applying it here would also
 * silently reinterpret patterns an operator has already stored. Reporting such
 * an entry is the fail-safe migration's job
 * (`includes/hardening-migration.php`, section 3, finding class `jeder-ua`,
 * `wirkung: aktiv`): it names the entry and leaves the decision with the
 * operator. `tests/test-bypass-roots.php` section 4a pins both halves.
 *
 * @param string $subject               The string to test.
 * @param mixed  $patterns              A list of patterns; non-arrays return false.
 * @param bool   $empty_subject_matches What an empty subject means for this call
 *                                      site. Default false (previous behaviour).
 * @param bool   $allow_catch_all       Whether a bare `*` pattern is honoured.
 *                                      Default true (previous behaviour).
 */
function creationell_captcha_wildcard_match(
    string $subject,
    $patterns,
    bool $empty_subject_matches = false,
    bool $allow_catch_all = true
): bool {
    if ( ! is_array( $patterns ) ) {
        return false;
    }
    foreach ( $patterns as $pattern ) {
        $pattern = trim( (string) $pattern );
        if ( '' === $pattern ) {
            continue;
        }
        if ( ! $allow_catch_all && '' === trim( $pattern, '*' ) ) {
            creationell_captcha_log( 'wildcard-match: catch-all pattern "' . $pattern . '" refused for this list' );
            continue;
        }
        if ( '' === $subject ) {
            if ( $empty_subject_matches ) {
                return true;
            }
            continue;
        }
        $regex = '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#i';
        if ( 1 === preg_match( $regex, $subject ) ) {
            return true;
        }
    }
    return false;
}

/**
 * Returns the canonical list of private/loopback CIDR ranges used when the
 * `firewall_trust_private_ranges` toggle is active.
 *
 * @return string[]
 */
function creationell_captcha_private_ranges(): array {
    return [
        '127.0.0.0/8',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '::1/128',
        'fc00::/7',
    ];
}

/**
 * Reads the optional `CREATIONELL_CAPTCHA_TRUSTED_PROXIES` wp-config constant
 * as a list. Accepts either a string array or a comma/whitespace-separated
 * scalar; invalid entries are dropped.
 *
 * @return string[]
 */
function creationell_captcha_trusted_proxies_constant(): array {
    if ( ! defined( 'CREATIONELL_CAPTCHA_TRUSTED_PROXIES' ) ) {
        return [];
    }

    $raw = CREATIONELL_CAPTCHA_TRUSTED_PROXIES;
    if ( is_array( $raw ) ) {
        $entries = $raw;
    } elseif ( is_string( $raw ) ) {
        $entries = preg_split( '/[\s,]+/', $raw ) ?: [];
    } else {
        return [];
    }

    $clean = [];
    foreach ( $entries as $entry ) {
        $entry = trim( (string) $entry );
        if ( '' !== $entry && creationell_captcha_is_valid_ip_or_cidr( $entry ) ) {
            $clean[] = $entry;
        }
    }
    return $clean;
}

/**
 * Whether the given IP belongs to a trusted upstream proxy.
 *
 * Sources are checked in this order; the first match wins:
 *   1. firewall_trusted_proxies (the explicit textarea list)
 *   2. CREATIONELL_CAPTCHA_TRUSTED_PROXIES (wp-config constant)
 *   3. firewall_trust_private_ranges (when on): the private/loopback ranges
 *   4. firewall_trust_cloudflare (when on): the cached/bundled CF ranges
 *
 * @param string $ip A validated client IP address.
 */
function creationell_captcha_is_trusted_proxy( string $ip ): bool {
    if ( '' === $ip ) {
        return false;
    }

    $settings = creationell_captcha_get_settings();

    if ( creationell_captcha_ip_in_list( $ip, (array) ( $settings['firewall_trusted_proxies'] ?? [] ) ) ) {
        return true;
    }

    if ( creationell_captcha_ip_in_list( $ip, creationell_captcha_trusted_proxies_constant() ) ) {
        return true;
    }

    if ( ! empty( $settings['firewall_trust_private_ranges'] )
        && creationell_captcha_ip_in_list( $ip, creationell_captcha_private_ranges() )
    ) {
        return true;
    }

    if ( ! empty( $settings['firewall_trust_cloudflare'] )
        && function_exists( 'creationell_captcha_cloudflare_ranges' )
        && creationell_captcha_ip_in_list( $ip, creationell_captcha_cloudflare_ranges() )
    ) {
        return true;
    }

    return false;
}

/**
 * Pure bypass evaluator — checks the three bypass sources against the supplied
 * inputs without touching $_SERVER, $_COOKIE or any static cache. The caller
 * is responsible for providing the values.
 *
 * Sources are checked in this order; the first match wins:
 *   1. firewall_ip_allow vs $ip
 *   2. bypass_ua_allow   vs $ua
 *   3. bypass_cookies    vs $cookies (strict name=value)
 *
 * @param string|null              $ip      Client IP, or null to skip the IP check.
 * @param string|null              $ua      User-Agent, or null to skip the UA check.
 * @param array<string, string>    $cookies Cookie map (name => value).
 * @return array{reason: string, source: string}|false
 */
function creationell_captcha_evaluate_bypass( ?string $ip, ?string $ua, array $cookies ): array|false {
    $settings = creationell_captcha_get_settings();

    // 1. IP allowlist.
    if ( null !== $ip && '' !== $ip ) {
        $list = (array) ( $settings['firewall_ip_allow'] ?? [] );
        if ( creationell_captcha_ip_in_list( $ip, $list ) ) {
            return [
                'reason' => 'IP-Allowlist',
                'source' => $ip,
            ];
        }
    }

    // 2. User-Agent bypass.
    if ( null !== $ua && '' !== $ua ) {
        $patterns = (array) ( $settings['bypass_ua_allow'] ?? [] );
        // BK-9: this list GRANTS a bypass on a header the client picks freely,
        // so both open ends of the matcher are nailed down here — a request
        // without a User-Agent is never waved through, and a bare `*` (which
        // would wave through every request there is) is refused. An admin who
        // truly wants that must not be able to do it by accident.
        //
        // The second half of that is a SYNTACTIC guard and no more: `*/*` is
        // not a bare star, passes it, and does wave through every request there
        // is — measured, not assumed. It is deliberately NOT neutralised here
        // (reasons in the docblock of creationell_captcha_wildcard_match());
        // the fail-safe migration reports such an entry as `wirkung: aktiv`
        // and the operator decides.
        if ( creationell_captcha_wildcard_match( $ua, $patterns, false, false ) ) {
            return [
                'reason' => 'UA-Bypass',
                'source' => $ua,
            ];
        }
    }

    // 3. Cookie bypass (strict name=value, exact match).
    $entries = (array) ( $settings['bypass_cookies'] ?? [] );
    foreach ( $entries as $entry ) {
        $entry = (string) $entry;
        $pos   = strpos( $entry, '=' );
        if ( false === $pos ) {
            continue;
        }
        $name     = substr( $entry, 0, $pos );
        $expected = substr( $entry, $pos + 1 );
        // BK-14: an entry without a value (`freepass=`) turns the comparison
        // below into hash_equals('', '') — true for anyone who sends the bare
        // cookie name. The validator refuses such entries on input, but that
        // only guards what is written from now on; this guard also covers the
        // ones already sitting in the option.
        if ( '' === $name || '' === $expected || ! array_key_exists( $name, $cookies ) ) {
            continue;
        }
        if ( hash_equals( $expected, (string) $cookies[ $name ] ) ) {
            return [
                'reason' => 'Cookie-Bypass',
                'source' => $name,
            ];
        }
    }

    return false;
}

/**
 * Whether the current request is allowed to bypass captcha, under-attack and
 * firewall protections. Reads $_SERVER, $_COOKIE and the request's client IP,
 * then delegates to `creationell_captcha_evaluate_bypass()`.
 *
 * Result is memoised for the request — settings, IP and cookies do not change
 * within a single PHP request. Only `reason` flows into the event-log context;
 * `source` is exposed for diagnostic logging by callers.
 *
 * @return array{reason: string, source: string}|false
 */
function creationell_captcha_request_bypassed(): array|false {
    static $cache = null;
    if ( null !== $cache ) {
        return $cache;
    }

    $ip = creationell_captcha_get_client_ip();
    $ua = isset( $_SERVER['HTTP_USER_AGENT'] )
        ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] )
        : '';

    $cookies = [];
    foreach ( (array) $_COOKIE as $name => $value ) {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared verbatim, not echoed.
        $cookies[ (string) $name ] = (string) wp_unslash( $value );
    }

    $cache = creationell_captcha_evaluate_bypass( $ip, $ua, $cookies );
    return $cache;
}

/**
 * Validates a single interceptor-action pattern.
 *
 * Allowed: lowercase/uppercase letters, digits, `_`, `-`, `*` (wildcard),
 * with an optional leading `!` for exclusion patterns. Empty input or
 * patterns of only `!` are rejected.
 *
 * @param string $entry Raw entry (already trimmed by the caller).
 * @return string|null  Normalised entry, or null if invalid.
 */
function creationell_captcha_validate_action_pattern( string $entry ): ?string {
    if ( '' === $entry ) {
        return null;
    }
    $candidate = ( '!' === $entry[0] ) ? substr( $entry, 1 ) : $entry;
    if ( '' === $candidate || 1 !== preg_match( '/^[A-Za-z0-9_*-]+$/', $candidate ) ) {
        return null;
    }
    return $entry;
}

/**
 * Validates a single bypass-cookie entry of the form `name=value`.
 *
 * Name must be alphanumeric, `_` or `-`. The value is length-capped to 200
 * bytes and passed through `sanitize_text_field()`; an entry whose value is
 * empty — before or after sanitising — is refused (BK-14): `hash_equals('','')`
 * is true, so such an entry would let anybody past who sends the bare cookie
 * name. A bypass cookie is a shared secret; a secret of zero length is none.
 *
 * @param string $entry Raw entry (already trimmed by the caller).
 * @return string|null  Normalised `name=value` entry, or null if invalid.
 */
function creationell_captcha_validate_cookie_entry( string $entry ): ?string {
    if ( '' === $entry ) {
        return null;
    }
    $pos = strpos( $entry, '=' );
    if ( false === $pos ) {
        return null;
    }
    $name  = trim( substr( $entry, 0, $pos ) );
    $value = substr( $entry, $pos + 1 );
    if ( '' === $name || 1 !== preg_match( '/^[A-Za-z0-9_-]+$/', $name ) ) {
        return null;
    }
    if ( strlen( $value ) > 200 ) {
        return null;
    }
    $value = sanitize_text_field( $value );
    if ( '' === $value ) {
        return null;
    }
    return $name . '=' . $value;
}

/**
 * Truncates an IP for DSGVO-compliant storage. IPv4 → last octet zeroed,
 * IPv6 → last 80 bits zeroed. Invalid IPs return ''.
 *
 * I2: an IPv4-mapped address is canonicalised first. Without that every such
 * client reduced to `::` — one value for the whole IPv4 internet, which made
 * the event log useless AND emptied the network half of the under-attack pass
 * binding (BK-3). Callers normally pass `creationell_captcha_get_client_ip()`,
 * which canonicalises already; this repeats it for the direct callers.
 *
 * @param string $ip A validated client IP address.
 */
function creationell_captcha_anonymize_ip( string $ip ): string {
    if ( '' === $ip ) {
        return '';
    }

    $ip = creationell_captcha_normalize_ip( $ip );

    if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
        $parts    = explode( '.', $ip );
        $parts[3] = '0';
        return implode( '.', $parts );
    }

    if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
        $bin = @inet_pton( $ip );
        if ( false === $bin || 16 !== strlen( $bin ) ) {
            return '';
        }
        // Keep first 48 bits (6 bytes), zero the remaining 80 bits (10 bytes).
        $truncated = substr( $bin, 0, 6 ) . str_repeat( "\0", 10 );
        $address   = @inet_ntop( $truncated );
        return is_string( $address ) ? $address : '';
    }

    return '';
}

/**
 * Returns a JSON-encoded fingerprint of $_POST: { field-name: value-byte-length }.
 *
 * No values are recorded — only structural metadata for attack-pattern
 * diagnosis. Field names that contain known sensitive substrings (password,
 * iban, api_key, …) are replaced with `[masked:<8-char-sha256>]` so the
 * fingerprint does not leak custom-form schema (e.g. `bank_iban_input`).
 * Output is length-capped to 2048 bytes; if longer, the JSON is collapsed
 * to "{}" rather than truncated mid-entry.
 */
function creationell_captcha_request_body_fingerprint(): string {
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- structural metadata only.
    if ( empty( $_POST ) || ! is_array( $_POST ) ) {
        return '';
    }

    /**
     * Filters the lower-cased substring patterns that mark a $_POST field
     * name as sensitive in the request-body fingerprint. Matching names are
     * stored as `[masked:<hash>]` so neither the name nor the value leaks
     * into the persistent event log.
     *
     * @since 0.25.0
     * @param string[] $patterns Lower-cased substrings (substring-match).
     */
    $sensitive_patterns = (array) apply_filters(
        'creationell_captcha_request_body_sensitive_patterns',
        [ 'password', 'passwort', 'secret', 'apikey', 'api_key', 'api-key', 'token', 'iban', 'cvv', 'cvc', 'private_key', 'privkey', 'ssn' ]
    );

    $map = [];
    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    foreach ( $_POST as $key => $value ) {
        $key = (string) $key;
        if ( strlen( $key ) > 64 ) {
            $key = substr( $key, 0, 64 );
        }

        $lower = strtolower( $key );
        foreach ( $sensitive_patterns as $pattern ) {
            $pattern = (string) $pattern;
            if ( '' !== $pattern && false !== strpos( $lower, $pattern ) ) {
                $key = '[masked:' . substr( hash( 'sha256', $key ), 0, 8 ) . ']';
                break;
            }
        }

        if ( is_array( $value ) ) {
            $map[ $key ] = count( $value );
        } else {
            $map[ $key ] = strlen( (string) $value );
        }
    }

    $json = wp_json_encode( $map, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );
    if ( false === $json || strlen( $json ) > 2048 ) {
        return '{}';
    }
    return $json;
}

/**
 * Sends a fail-closed block response and terminates the request.
 *
 * @param int    $status      HTTP status code (403 firewall, 429 rate limit).
 * @param string $message     The message shown to the client.
 * @param int    $retry_after Optional Retry-After value in seconds.
 */
function creationell_captcha_block_response( int $status, string $message, int $retry_after = 0 ): void {
    if ( $retry_after > 0 && ! headers_sent() ) {
        header( 'Retry-After: ' . $retry_after );
    }

    $is_ajax = false;
    if ( isset( $_SERVER['HTTP_X_REQUESTED_WITH'] )
        && 'xmlhttprequest' === strtolower( (string) wp_unslash( $_SERVER['HTTP_X_REQUESTED_WITH'] ) )
    ) {
        $is_ajax = true;
    } elseif ( isset( $_SERVER['HTTP_ACCEPT'] )
        && str_contains( strtolower( (string) wp_unslash( $_SERVER['HTTP_ACCEPT'] ) ), 'application/json' )
    ) {
        $is_ajax = true;
    }

    if ( $is_ajax ) {
        wp_send_json_error( [ 'message' => $message ], $status );
    }

    wp_die(
        esc_html( $message ),
        esc_html( $message ),
        [ 'response' => $status ]
    );
}

/**
 * Base64URL encoder (RFC 4648 §5) — strips standard-base64 padding and
 * replaces +/ with -_ so the value is URL-safe.
 *
 * @param string $bytes Raw bytes to encode.
 */
function creationell_captcha_base64url_encode( string $bytes ): string {
    return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
}

/**
 * Base64URL decoder — accepts unpadded URL-safe input and returns the raw
 * bytes. Returns the empty string on malformed input (no exceptions).
 *
 * @param string $encoded URL-safe base64 string.
 */
function creationell_captcha_base64url_decode( string $encoded ): string {
    $padded  = $encoded . str_repeat( '=', ( 4 - ( strlen( $encoded ) % 4 ) ) % 4 );
    $decoded = base64_decode( strtr( $padded, '-_', '+/' ), true );
    return false === $decoded ? '' : $decoded;
}

/**
 * Reads the current rate-limit counter for an IP without incrementing it.
 *
 * Uses the same bucket key as `Creationell\Captcha\RateLimiter::run()` so the
 * value matches what the run-loop would see. Returns 0 if no transient exists
 * for the current window.
 *
 * @param string $ip Client IP (call `creationell_captcha_get_client_ip()`).
 */
function creationell_captcha_ratelimit_current_count( string $ip ): int {
    if ( '' === $ip ) {
        return 0;
    }
    $settings = creationell_captcha_get_settings();
    $window   = max( 10, min( 3600, (int) ( $settings['ratelimit_window'] ?? 300 ) ) );
    $bucket   = (int) floor( time() / $window );
    $key      = 'creationell_captcha_rl_' . substr( hash( 'sha256', $ip ), 0, 32 ) . '_' . $bucket;
    return (int) get_transient( $key );
}
