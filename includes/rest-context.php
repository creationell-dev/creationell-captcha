<?php
/**
 * Root helpers for the question "what request is this?" — which PATH does it
 * address, and is it served by the REST API?
 *
 * Both answers used to be reconstructed ad hoc at every call site, and both
 * were wrong in the same way: they trusted a value that looks authoritative
 * but is not (`?rest_route=` for REST-ness, `wp_parse_url()` for the path).
 *
 * Audit module 27, findings BK-1 / BK-2 / CM-7: two guards derived REST-ness
 * from the raw, client-controlled `rest_route` request parameter — the
 * interceptor via a bare `isset()`, the rate limiter via `str_contains()`.
 * Both were bypassable by simply appending `?rest_route=` (BK-1) or
 * `?rest_route=…challenge` (BK-2) to a request that WordPress never serves
 * through the REST API at all. The same value-independent-existence pattern
 * had already come back once as a regression in the login gate. It therefore
 * lives here exactly once, and every consumer calls into it.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Returns the path portion of the current request, the way WordPress core
 * derives it — NOT the way a URL parser would.
 *
 * The return value is still percent-encoded (the "wire spelling"); callers that
 * need the decoded form apply `rawurldecode()` to it exactly once, after this
 * function has split off the query.
 *
 * WHY THIS EXISTS (audit module 27, finding C1)
 * ---------------------------------------------
 * Every call site used to run `wp_parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH )`.
 * `wp_parse_url()` is a URL parser, and `REQUEST_URI` is not a URL — it is a
 * request target. For a target that starts with `//` the parser treats the
 * string as a scheme-relative URL (it prepends `placeholder:`, see
 * `wp-includes/http.php`), so the first segment becomes the HOST:
 *
 *     REQUEST_URI      wp_parse_url(…, PHP_URL_PATH)   WP::parse_request()
 *     /kontakt/        '/kontakt/'                     kontakt
 *     //kontakt/       '/'                             kontakt   ← same page
 *     ///kontakt/      ''                              kontakt   ← same page
 *
 * Core reduces the target in `WP::parse_request()` with
 * `list( $req_uri ) = explode( '?', $_SERVER['REQUEST_URI'] ); $req_uri = trim( $req_uri, '/' );`
 * (`wp-includes/class-wp.php`) and therefore routes all three spellings to the
 * same page. The guards saw `/` or `''`, matched no pattern, and let the
 * request through: `POST //kontakt` was a one-character bypass of the entire
 * interceptor path guard.
 *
 * WHAT THIS DOES
 * --------------
 * 1. Split off query and fragment BEFORE anything is decoded, so a
 *    percent-encoded `?` inside the path cannot smuggle a query string in.
 * 2. Strip scheme and authority if the target arrived in absolute form
 *    (`POST http://example.com/kontakt HTTP/1.1`, RFC 9112 §3.2.2). Core does
 *    not do this and simply 404s such a request, but `wp_parse_url()` did — so
 *    keeping it guards MORE than core routes, never less. Dropping it would
 *    have taken protection away that 1.0.2 had.
 * 3. Collapse leading slashes to exactly one — the same reduction core's
 *    `trim( $req_uri, '/' )` performs. INNER double slashes are kept, because
 *    core keeps them too, and the TRAILING slash is kept, because existing
 *    patterns are written against the spelling `wp_parse_url()` produced.
 *
 * @since 1.1.0
 *
 * @return string Request path with exactly one leading slash, still encoded.
 */
function creationell_captcha_request_path(): string {
    $uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

    // Query first, then fragment — same order of precedence parse_url() has for
    // a path-only target, and the result is identical either way.
    $path = explode( '#', explode( '?', $uri, 2 )[0], 2 )[0];

    /*
     * Absolute request form. The scheme must sit at the very START, so a path
     * that merely CONTAINS "://" (e.g. /weiter/http://example.com/x) is left
     * alone. Scheme grammar per RFC 3986 §3.1.
     */
    if ( 1 === preg_match( '#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', $path ) ) {
        $authority_and_path = substr( $path, (int) strpos( $path, '://' ) + 3 );
        $first_slash        = strpos( $authority_and_path, '/' );
        $path               = false === $first_slash ? '/' : substr( $authority_and_path, $first_slash );
    }

    return '/' . ltrim( $path, '/' );
}

/**
 * Der aktuelle Request als relativer Ziel-URI: Pfad aus
 * `creationell_captcha_request_path()`, Query aus derselben Zeichenkette.
 *
 * WARUM DAS EINE EIGENE FUNKTION IST (Nachlese Modul 27, Strang N1; Umfang
 * erweitert im Re-Review und in der Nachlese N6)
 * ---------------------------------------------------------------------
 * `remove_query_arg()` OHNE URL-Argument und `add_query_arg()` ohne URL-
 * Argument sind dieselbe Mechanik: beide delegieren an `add_query_arg()`, und
 * dessen Zweig `count( $args ) < 3` (bzw. `< 2` bei der Array-Form) liest
 * `$_SERVER['REQUEST_URI']` ROH. Sie leiten also eine Pfadangabe aus dem
 * Request ab, ohne das sichtbar zu tun — deshalb standen die betroffenen
 * Stellen in keinem der vier Review-Berichte.
 *
 * Gemessen wurde das am Ausblenden-Link des Härtungs-Hinweises: bei
 * `REQUEST_URI = "//wp-admin/admin.php?page=…"` rendert er ein
 * protokollrelatives `href="//wp-admin/admin.php?…"`; `esc_url()` reicht jede
 * mit `/` beginnende Zeichenkette unverändert durch. Der Browser liest das als
 * Host `wp-admin`, der Klick kommt nie an. Dieselbe Konstruktion stand am
 * „↻ Aktualisieren"-Link der Statistik-Seite.
 *
 * Die Query kommt bewusst aus DERSELBEN Zeichenkette wie der Pfad, damit
 * beide Hälften zusammenpassen und nicht die eine aus `REQUEST_URI` und die
 * andere aus `QUERY_STRING` stammt (die beiden können auseinanderlaufen, etwa
 * hinter einer Rewrite-Regel). Und der Rückgabewert ist bewusst RELATIV: er
 * ersetzt genau das, was der Kern ohne URL-Argument selbst eingesetzt hätte.
 *
 * VOLLZÄHLIGKEIT: Seit der Nachlese N6 übergibt jeder
 * `add_query_arg()`/`remove_query_arg()`-Aufruf im ausgelieferten Code eine
 * explizite URL — entweder diese Funktion, eine `$base_url` aus
 * `menu_page_url()` oder `admin_url()`. Nachgezählt wird das nicht von Hand,
 * sondern von `tests/test-hardening-migration.php` (Abschnitt „Bestandsaufnahme"),
 * das alle Aufrufe unter `includes/` auszählt und rot wird, sobald einer wieder
 * ohne URL-Argument dasteht. Ein früherer Stand dieses Docblocks nannte die
 * Redirect-Funktion der Härtungs-Migration „die neunte und letzte Stelle im
 * Plugin, die eine Pfadangabe aus dem Request ableitet" — das war messbar
 * falsch und ist hiermit ersetzt.
 *
 * @since 1.1.0
 *
 * @return string Relativer Ziel-URI (führender Schrägstrich, genau einer).
 */
function creationell_captcha_request_target(): string {
    $uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

    // Query abtrennen, Fragment verwerfen — dieselbe Reihenfolge wie in
    // creationell_captcha_request_path(), das die Pfad-Hälfte liefert.
    $parts = explode( '?', $uri, 2 );
    $query = isset( $parts[1] ) ? explode( '#', $parts[1], 2 )[0] : '';

    $target = creationell_captcha_request_path();
    if ( '' !== $query ) {
        $target .= '?' . $query;
    }

    return $target;
}

/**
 * Returns the REST route the current request actually addresses.
 *
 * Returns a normalised route (leading slash, no trailing slash, no query
 * part) — for example `/creationell-captcha/v1/challenge` — or the empty
 * string when the request is *not* served by the REST API.
 *
 * The function is deliberately conservative: whenever it cannot establish
 * that WordPress core will hand the request to the REST server, it returns
 * the empty string. Both consumers fail closed on that answer (the
 * interceptor guards the request, the rate limiter counts it), so
 * under-detection is safe while over-detection hands out a bypass.
 *
 * It must work at `init` priority 0/1, i.e. long before `parse_request` has
 * populated `$GLOBALS['wp']->query_vars` and before core defines the
 * `REST_REQUEST` constant, so it reconstructs core's own decision from the
 * request instead of reading either of those.
 *
 * @since 1.1.0
 *
 * @return string Normalised REST route, or '' when this is not a REST request.
 */
function creationell_captcha_current_rest_route(): string {
    /*
     * (1) Which script serves the request?
     *
     * `rest_api_loaded()` is hooked to `parse_request` (wp-includes/
     * default-filters.php:535), and `parse_request` only runs from `wp()` —
     * which core calls in exactly one place, wp-blog-header.php:16, i.e. the
     * front controller index.php. wp-login.php, wp-comments-post.php,
     * xmlrpc.php, wp-cron.php and every wp-admin/*.php entry point load
     * WordPress without ever parsing the request, so a `rest_route`
     * parameter is completely inert there. That inertness is BK-2: a
     * `POST /wp-login.php?rest_route=…challenge` is a plain login POST and
     * must be rate limited like any other.
     *
     * Allow-list rather than deny-list on purpose — an unknown entry point
     * yields "not REST", which is the fail-closed answer.
     */
    $script = isset( $_SERVER['SCRIPT_NAME'] ) ? (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) : '';
    if ( 'index.php' !== basename( $script ) ) {
        return '';
    }
    // wp-admin/index.php is the dashboard, not the front controller; it never
    // calls wp() either. Same test core itself uses on PHP_SELF in
    // WP::parse_request().
    if ( str_contains( $script, 'wp-admin/' ) ) {
        return '';
    }

    $prefix = trim( (string) rest_get_url_prefix(), '/' );

    // Request path relative to the site's home path, with an optional
    // `index.php` segment (PATHINFO permalinks) removed — the same
    // normalisation WP::parse_request() performs before matching the rewrite
    // rules. The path comes from creationell_captcha_request_path(), which
    // splits off the query before anything is decoded AND collapses leading
    // slashes; with the old wp_parse_url() call `//kontakt/` produced an empty
    // $rel, and an empty $rel IS the REST entry path (C1).
    $rel = ltrim( creationell_captcha_request_path(), '/' );

    // home_url() really is a URL, so wp_parse_url() is the right tool here.
    $home = trim( (string) wp_parse_url( (string) home_url(), PHP_URL_PATH ), '/' );
    if ( '' !== $home ) {
        if ( 0 === stripos( $rel, $home . '/' ) ) {
            $rel = substr( $rel, strlen( $home ) + 1 );
        } elseif ( 0 === strcasecmp( $rel, $home ) ) {
            $rel = '';
        }
    }
    if ( 'index.php' === $rel ) {
        $rel = '';
    } elseif ( str_starts_with( $rel, 'index.php/' ) ) {
        $rel = substr( $rel, strlen( 'index.php/' ) );
    }
    $rel = rtrim( $rel, '/' );

    /*
     * (2) An explicit `rest_route` request parameter.
     *
     * Core reads it as a public query var in WP::parse_request(): $_POST wins
     * over $_GET, and if both are present with *different* values core aborts
     * the whole request with a 400 ("A variable mismatch has been detected.")
     * — neither the REST server nor the page runs, so that case is "not REST"
     * for us as well.
     */
    $has_post = isset( $_POST['rest_route'] );
    $has_get  = isset( $_GET['rest_route'] );

    if ( $has_post || $has_get ) {
        /*
         * The parameter decouples REST-ness from the requested path: core
         * dispatches the REST server no matter which URL carried it. Left
         * unchecked that hands an attacker a universal excuse — appending
         * `?rest_route=/wp/v2/types` to `POST /kontakt/` would switch the
         * interceptor off for a guarded path, while everything hooked to
         * `init` (which runs BEFORE parse_request) had already executed. That
         * is the wider shape of BK-1, beyond the empty-value repro.
         *
         * Core's own rest_url() only ever produces the parameter on the home
         * path (`https://example.com/?rest_route=/…`, optionally with the
         * `index.php` segment); every real client therefore lands here with an
         * empty relative path. Requests under the REST url prefix are accepted
         * as well because they are unambiguously REST either way. Anything
         * else keeps its own path's protection.
         */
        $is_rest_entry_path = ( '' === $rel )
            || ( '' !== $prefix && ( $rel === $prefix || str_starts_with( $rel, $prefix . '/' ) ) );

        if ( ! $is_rest_entry_path ) {
            return '';
        }

        // phpcs:ignore WordPress.Security.NonceVerification -- read-only request classification, mirrors WP::parse_request().
        $raw = $has_post ? wp_unslash( $_POST['rest_route'] ) : wp_unslash( $_GET['rest_route'] );

        // phpcs:ignore WordPress.Security.NonceVerification -- read-only request classification.
        if ( $has_post && $has_get && wp_unslash( $_POST['rest_route'] ) !== wp_unslash( $_GET['rest_route'] ) ) {
            return '';
        }

        /*
         * A non-string query var (`?rest_route[]=…`) never reaches a REST
         * dispatch: rest_api_loaded() hands the array on to
         * untrailingslashit()/rest_get_server()->serve_request(), which runs
         * into a TypeError. Measured live, that surfaces as an HTTP 500
         * (WordPress error page), NOT as the 400 this comment used to claim —
         * the conclusion "no REST dispatch" holds, the named mechanism did not.
         */
        if ( ! is_string( $raw ) ) {
            return '';
        }

        return creationell_captcha_normalize_rest_route( $raw );
    }

    /*
     * (3) The pretty-permalink form under the REST url prefix.
     *
     * Core registers the rewrite rules in rest_api_register_rewrites()
     * (wp-includes/rest-api.php:226-229):
     *   ^wp-json/?$              → index.php?rest_route=/
     *   ^wp-json/(.*)?           → index.php?rest_route=/$matches[1]
     *   ^index.php/wp-json/…     → same, for PATHINFO permalinks
     * They are anchored at the start of the request path (after the home
     * path) and matched case-sensitively — `/kontakt/wp-json/` is therefore
     * NOT a REST request, although the pre-fix substring check in
     * Interceptor::is_rest_request() treated it as one.
     */
    if ( '' === $prefix ) {
        return '';
    }

    if ( $rel !== $prefix && ! str_starts_with( $rel, $prefix . '/' ) ) {
        return '';
    }

    // substr() keeps the '/' that separates prefix and route, which is exactly
    // the leading slash core's rewrite target ("/$matches[1]") produces.
    // `/wp-json` and `/wp-json/` yield '' and are normalised to '' below.
    return creationell_captcha_normalize_rest_route( substr( $rel, strlen( $prefix ) ) );
}

/**
 * Normalises a raw `rest_route` value into the plugin's canonical route form.
 *
 * Returns '' for every value that does not address a concrete REST route.
 *
 * @since 1.1.0
 *
 * @param string $raw Raw `rest_route` value as core would see it.
 * @return string Route with a leading slash and without a trailing one, or ''.
 */
function creationell_captcha_normalize_rest_route( string $raw ): string {
    /*
     * Core's own gate, verbatim: rest_api_loaded() (wp-includes/rest-api.php:441)
     * returns early on `empty( $GLOBALS['wp']->query_vars['rest_route'] )`.
     * PHP's empty() also covers the literal string '0', so `?rest_route=0`
     * renders the normal page and must NOT grant a bypass — that value
     * independence is the heart of BK-1.
     */
    if ( empty( $raw ) ) {
        return '';
    }

    // A percent-decoded '?' can smuggle a query string into the value; a route
    // never carries one.
    $pos = strpos( $raw, '?' );
    if ( false !== $pos ) {
        $raw = substr( $raw, 0, $pos );
    }

    // Core applies untrailingslashit() to the route (rest-api.php:476), which
    // is rtrim( $string, '/\\' ).
    $route = rtrim( $raw, '/\\' );

    /*
     * Slash-only values ('/', '//', '\') reduce to nothing. Core would fall
     * back to the REST index route '/' here; we deliberately report "no REST
     * request" instead, because such a value addresses no route of ours and
     * "not REST" is the fail-closed answer for both consumers (guard the
     * request / count the request). Requirement from the task brief.
     */
    if ( '' === $route ) {
        return '';
    }

    // `?rest_route=creationell-captcha/v1/challenge` (no leading slash) is the
    // spelling the audit repro for BK-2 uses. Normalising it means the
    // exact-route comparison in the rate limiter cannot be widened or narrowed
    // by mere spelling.
    if ( ! str_starts_with( $route, '/' ) ) {
        $route = '/' . $route;
    }

    return $route;
}
