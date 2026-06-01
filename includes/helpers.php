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
 * @param string $message Message to log.
 */
function creationell_captcha_log( string $message ): void {
    if ( defined( 'CREATIONELL_CAPTCHA_DEBUG' ) && CREATIONELL_CAPTCHA_DEBUG ) {
        error_log( '[creationell-captcha] ' . $message );
    }
}

/**
 * Resolves the client IP address.
 *
 * Returns the validated REMOTE_ADDR by default. When the `firewall_behind_proxy`
 * setting is on, the configured forwarded header is used instead — falling back
 * to REMOTE_ADDR if it yields no valid IP.
 */
function creationell_captcha_get_client_ip(): string {
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated via FILTER_VALIDATE_IP.
    $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
    $remote = filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';

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
    $choice     = (string) ( $settings['firewall_proxy_header'] ?? 'x-forwarded-for' );
    $server_key = $header_map[ $choice ] ?? 'HTTP_X_FORWARDED_FOR';

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

    if ( 'x-forwarded-for' === $choice ) {
        // Walk the XFF chain right-to-left, skipping trusted hops; the first
        // non-trusted, valid entry is the genuine client.
        $entries = array_reverse( array_map( 'trim', explode( ',', $raw ) ) );
        foreach ( $entries as $entry ) {
            if ( '' === $entry || false === filter_var( $entry, FILTER_VALIDATE_IP ) ) {
                continue;
            }
            if ( creationell_captcha_is_trusted_proxy( $entry ) ) {
                continue;
            }
            creationell_captcha_log( 'client-ip: ' . $entry . ' (via XFF, trusted remote ' . $remote . ')' );
            return $entry;
        }
        // Chain was entirely trusted (or empty/invalid) — bail to REMOTE_ADDR.
        return $remote;
    }

    // Single-value headers: X-Real-IP, CF-Connecting-IP, True-Client-IP.
    $candidate = trim( $raw );
    if ( false !== filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
        creationell_captcha_log( 'client-ip: ' . $candidate . ' (via ' . $choice . ', trusted remote ' . $remote . ')' );
        return $candidate;
    }

    return $remote;
}

/**
 * Whether an IP matches any entry in a list of IPs or CIDR ranges.
 *
 * @param string $ip   The client IP.
 * @param mixed  $list A list of IPs / CIDR ranges (non-arrays are ignored).
 */
function creationell_captcha_ip_in_list( string $ip, $list ): bool {
    if ( '' === $ip || ! is_array( $list ) ) {
        return false;
    }

    foreach ( $list as $entry ) {
        $entry = trim( (string) $entry );
        if ( '' === $entry ) {
            continue;
        }
        if ( str_contains( $entry, '/' ) ) {
            if ( creationell_captcha_ip_in_cidr( $ip, $entry ) ) {
                return true;
            }
        } elseif ( 0 === strcasecmp( $ip, $entry ) ) {
            return true;
        }
    }

    return false;
}

/**
 * Whether an IP falls within a CIDR range. Supports IPv4 and IPv6.
 *
 * @param string $ip   The client IP.
 * @param string $cidr A CIDR range, e.g. "203.0.113.0/24".
 */
function creationell_captcha_ip_in_cidr( string $ip, string $cidr ): bool {
    [ $subnet, $bits ] = array_pad( explode( '/', $cidr, 2 ), 2, '' );

    $ip_bin     = @inet_pton( $ip );
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
    return (int) $bits >= 0 && (int) $bits <= $max;
}

/**
 * Whether a subject matches any of the given wildcard patterns (case-insensitive).
 *
 * The pattern alphabet is the same as the firewall UA-blocklist: `*` is the
 * single wildcard, everything else is matched literally.
 *
 * @param string $subject  The string to test.
 * @param mixed  $patterns A list of patterns; non-arrays return false.
 */
function creationell_captcha_wildcard_match( string $subject, $patterns ): bool {
    if ( ! is_array( $patterns ) || '' === $subject ) {
        return false;
    }
    foreach ( $patterns as $pattern ) {
        $pattern = trim( (string) $pattern );
        if ( '' === $pattern ) {
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
        if ( creationell_captcha_wildcard_match( $ua, $patterns ) ) {
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
        if ( '' === $name || ! array_key_exists( $name, $cookies ) ) {
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
 * Name must be alphanumeric, `_` or `-`. Value may be empty and is
 * length-capped to 200 bytes. The returned entry has the value passed
 * through `sanitize_text_field()`.
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
    return $name . '=' . sanitize_text_field( $value );
}

/**
 * Truncates an IP for DSGVO-compliant storage. IPv4 → last octet zeroed,
 * IPv6 → last 80 bits zeroed. Invalid IPs return ''.
 *
 * @param string $ip A validated client IP address.
 */
function creationell_captcha_anonymize_ip( string $ip ): string {
    if ( '' === $ip ) {
        return '';
    }

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
