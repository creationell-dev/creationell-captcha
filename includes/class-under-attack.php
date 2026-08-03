<?php
/**
 * Under-attack mode — interstitial gate for anonymous visitors.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Gates anonymous front-end page views behind an interstitial proof-of-work
 * challenge while under-attack mode is active. See the module-5 design spec.
 */
class UnderAttack {

    /**
     * The pass cookie name.
     */
    private const COOKIE = 'creationell_captcha_ua_pass';

    /**
     * The interstitial form field carrying the solved challenge.
     */
    private const FIELD = 'creationell_captcha_ua';

    /**
     * Runs the under-attack gate. Registered on `template_redirect`. Terminates
     * the request when an interstitial is served or a pass redirect is issued.
     */
    public function run(): void {
        if ( creationell_captcha_is_disabled() ) {
            return;
        }

        $settings = creationell_captcha_get_settings();
        if ( empty( $settings['underattack_enabled'] ) ) {
            return;
        }

        // Logged-in users of any role are exempt.
        if ( is_user_logged_in() ) {
            return;
        }

        // Global bypass (IP allowlist, UA bypass, cookie bypass).
        if ( false !== creationell_captcha_request_bypassed() ) {
            return;
        }

        // A valid pass cookie lets the visitor through.
        if ( $this->has_valid_pass() ) {
            return;
        }

        // The interstitial form posts the solved challenge back.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the payload is the token.
        $solution = isset( $_POST[ self::FIELD ] ) ? wp_unslash( $_POST[ self::FIELD ] ) : '';
        if ( is_string( $solution ) && '' !== $solution && $this->redeem( $solution ) ) {
            // The visitor solved the challenge and the pass cookie was issued —
            // record the pass so the dashboard can tell "asked" from "passed".
            /** This action is documented in includes/rest.php. */
            do_action( 'creationell_captcha_event', 'underattack_passed', [ 'action' => 'underattack_passed' ] );

            wp_safe_redirect( $this->request_target() );
            exit;
        }

        $this->serve_interstitial();
    }

    /**
     * Redeems a posted interstitial solution: mints the pass FIRST, spends the
     * challenge SECOND, sets the cookie LAST.
     *
     * The order is the finding (m5). Before 1.1.0 the gate verified first and
     * issued afterwards — and verification claims the challenge's single-use
     * replay marker (`Engine::verify()`), so every failure of the issuing step
     * burned a proof-of-work the visitor had just completed and sent him back
     * to a fresh interstitial. Where the cause is per-request that costs one
     * extra PoW; where it is permanent — output already sent before
     * `template_redirect`, or no derivable HMAC key (m4) — it is an endless
     * loop of them, and nothing in the log said why.
     *
     * Minting has no side effect, so it can safely go first. Only the cookie is
     * set after the challenge is spent, and by then the two reasons the issuing
     * step can fail have already been ruled out.
     *
     * @param string $solution The raw payload from the interstitial form field.
     * @return bool True when the visitor passed AND the pass cookie was set.
     */
    private function redeem( string $solution ): bool {
        $pass = $this->mint_pass();
        if ( null === $pass ) {
            return false;
        }

        if ( ! $this->verify_gate_payload( $solution ) ) {
            return false;
        }

        return $this->commit_pass( $pass );
    }

    /**
     * The URL the interstitial posts back to, and the one the visitor returns
     * to after passing the gate.
     *
     * C1, sixth call site: both used to be the raw `REQUEST_URI`. Two distinct
     * consequences, neither of them cosmetic:
     *
     *  - As the form `action` the value is escaped with `esc_url()`, and
     *    `esc_url()` returns every string starting with `/` unchanged
     *    (`wp-includes/formatting.php`: `if ( '/' === $url[0] ) {
     *    $good_protocol_url = $url; }`). A request for `//fremder.host/x` —
     *    which WordPress happily serves, it just 404s — therefore produced
     *    `action="//fremder.host/x"`, a protocol-relative URL to a foreign
     *    host. The page auto-submits, so the browser POSTs the solved
     *    challenge there without the visitor doing anything.
     *  - As the redirect target `wp_validate_redirect()` does catch the foreign
     *    host, but it catches it by falling back to wp-admin: a LEGITIMATE
     *    visitor who requested `//kontakt/` passed the gate and then landed in
     *    the dashboard instead of on his page.
     *
     * `creationell_captcha_request_path()` collapses the leading slashes to
     * exactly one, which removes both. The query string is kept — dropping it
     * would send the visitor to a different page than the one he asked for
     * (`/shop/?s=stuhl`). The fragment is dropped because browsers never send
     * one.
     */
    private function request_target(): string {
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

        $query = '';
        $pos   = strpos( $uri, '?' );
        if ( false !== $pos ) {
            $query = explode( '#', substr( $uri, $pos + 1 ), 2 )[0];
        }

        $path = creationell_captcha_request_path();

        return '' === $query ? $path : $path . '?' . $query;
    }

    /**
     * Verifies the payload the interstitial posted back — as the under-attack
     * gate, which is the only caller allowed to redeem a challenge that was
     * issued under ctx suppression (FU-1).
     *
     * Deliberately NOT `creationell_captcha_verify_payload()` (includes/widget.php):
     * that helper is the FORM path, and the whole point of the marker is that
     * the form path keeps rejecting these challenges. The distinction is made
     * by this call site — it is a PHP argument, not a request field, so no
     * anonymous sender can claim it for himself.
     *
     * Everything else stays identical to the form helper: the kill switch is
     * already handled in run() above, and the base64 pre-check below is the
     * same one, kept so a junk field never reaches the decoder.
     *
     * @param string $payload The raw payload from the interstitial form field.
     */
    private function verify_gate_payload( string $payload ): bool {
        // ALTCHA payloads are base64 — reject anything outside that alphabet early.
        if ( ! preg_match( '#^[A-Za-z0-9+/]+={0,2}$#', $payload ) ) {
            return false;
        }

        return creationell_captcha_engine()->verify( $payload, true );
    }

    /**
     * Whether the request carries a valid, unexpired pass token that belongs
     * to THIS visitor.
     *
     * BK-3: the check used to be `hash_hmac('sha256', $expiry, $secret)` — the
     * MAC covered the expiry timestamp and nothing else. One solved
     * interstitial therefore produced a transferable bearer token: copy the
     * cookie value, hand it to any number of clients, and every one of them
     * walked past the gate until `underattack_pass_duration` (up to 86400 s)
     * ran out. The verification now happens against a token whose MAC also
     * covers a fingerprint of the visitor that the cookie does not carry —
     * see `creationell_captcha_underattack_pass_binding()` for the trade-off
     * and the filter that switches it off.
     */
    private function has_valid_pass(): bool {
        if ( ! isset( $_COOKIE[ self::COOKIE ] ) ) {
            return false;
        }

        return creationell_captcha_underattack_pass_check(
            (string) wp_unslash( $_COOKIE[ self::COOKIE ] )
        );
    }

    /**
     * Mints a fresh pass token WITHOUT setting anything.
     *
     * Both failure modes are permanent-until-fixed as often as they are
     * transient, and both leave the site behind a 503 that nobody can pass
     * (m4). `has_valid_pass()` fails closed for the same missing key, so the
     * gate is shut in both directions — which is the right direction, but the
     * operator used to get no hint at all: no log line, no doctor check, just a
     * site that stays down while visitors solve proof-of-work after
     * proof-of-work. Hence the two log lines below.
     *
     * @return array{token: string, expiry: int}|null Null when no pass could be
     *                                                minted.
     */
    private function mint_pass(): ?array {
        if ( headers_sent() ) {
            // Something wrote output before `template_redirect`. A BOM in a
            // theme file, a stray echo on `init`, a notice with display_errors
            // on — all of those happen on EVERY request, and then no visitor
            // can ever be handed a pass cookie.
            creationell_captcha_log(
                'under-attack: pass cookie cannot be set — output was already sent before template_redirect. No visitor can pass the gate until that is fixed.'
            );

            return null;
        }

        $settings = creationell_captcha_get_settings();
        $duration = max( 300, min( 86400, (int) ( $settings['underattack_pass_duration'] ?? 3600 ) ) );

        $expiry = time() + $duration;
        // Bound to this visitor (BK-3) and signed with a key derived for this
        // one purpose (Wurzel 3.5), so the value is worthless to any other
        // token check in the plugin and to any client outside the issuing
        // network. Precisely: the network is the half a recipient cannot bring
        // along; the User-Agent half he copies together with the cookie.
        $token = creationell_captcha_underattack_pass_issue( $expiry );
        if ( '' === $token ) {
            creationell_captcha_log(
                'under-attack: no pass token could be minted — no HMAC secret is derivable. No visitor can pass the gate; check the creationell_captcha_secrets option or set CREATIONELL_CAPTCHA_HMAC_SECRET.'
            );

            return null;
        }

        return [
            'token'  => $token,
            'expiry' => $expiry,
        ];
    }

    /**
     * Sets a minted pass token as the visitor's cookie.
     *
     * @param array{token: string, expiry: int} $pass Value from `mint_pass()`.
     * @return bool True when the cookie was handed to PHP.
     */
    private function commit_pass( array $pass ): bool {
        return setcookie(
            self::COOKIE,
            $pass['token'],
            [
                'expires'  => $pass['expiry'],
                'path'     => '/',
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]
        );
    }

    /**
     * Outputs the interstitial page with HTTP 503 and terminates.
     */
    private function serve_interstitial(): void {
        /** This action is documented in includes/rest.php. */
        do_action( 'creationell_captcha_event', 'underattack', [ 'action' => 'underattack' ] );

        if ( ! headers_sent() ) {
            status_header( 503 );
            // m7: this page must not be stored anywhere. The ctx token inside
            // it is single-use, so a replayed copy hands the invisible widget a
            // challenge it cannot solve. nocache_headers() already sends
            // `no-store, private` (checked against the core of the test
            // instance) — a cache that ignores that is a deployment problem
            // this file cannot solve; see the ctx issuer in includes/helpers.php.
            nocache_headers();
            header( 'Content-Type: text/html; charset=utf-8' );
        }

        // C1: normalised, not the raw REQUEST_URI — see request_target(). The
        // template escapes this with esc_url(), and esc_url() waves every
        // string starting with `/` straight through, so `//fremder.host/x`
        // would have become a protocol-relative form action on an auto-
        // submitting page.
        $action     = $this->request_target();
        $widget_src = CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/altcha.min.js';

        // ?ctx=<token> signals the /challenge handler to skip the code-
        // challenge attachment — the interstitial widget is invisible and
        // cannot show a code modal, so a code-challenge here would deadlock
        // the gate.
        //
        // BK-4/W5: the old token was the same HMAC for every visitor inside a
        // five-minute bucket and was accepted for two buckets, so the value we
        // hand to this browser was a ten-minute, freely transferable licence to
        // switch the second captcha stage off. "Cannot be forged" was never the
        // question — it is printed in the page we serve to anonymous clients.
        //
        // The token minted here is single-use and expires after two minutes;
        // that closes the replay and shortens the window. It is NOT bound to
        // anything the recipient fails to bring along: the MAC covers the
        // User-Agent, and a User-Agent is whatever the sender types into the
        // header. Every 503 we serve therefore still hands out one usable
        // suppression ticket — usable by the fetcher, or by whoever he passes
        // the URL and the UA string to. See the issuer for why no address is
        // bound in here.
        //
        // What the ticket is worth is capped elsewhere (FU-1): the challenge
        // `/challenge` returns for an accepted ctx is marked under-attack-only
        // inside its signed parameters, and Engine::verify() redeems such a
        // challenge only for this gate — verify_gate_payload() below. Getting
        // a suppression ticket is still one GET; spending it at a protected
        // form is not possible any more.
        //
        // add_query_arg() instead of the previous '?ctx=' concatenation: with
        // plain permalinks rest_url() already carries a query string
        // (`?rest_route=…`), and a second `?` dropped the parameter — which
        // with the code challenge active means the invisible widget receives
        // an image code it cannot show.
        $ctx_token     = creationell_captcha_underattack_ctx_issue();
        $challenge_url = rest_url( 'creationell-captcha/v1/challenge' );
        if ( '' !== $ctx_token ) {
            $challenge_url = add_query_arg( 'ctx', $ctx_token, $challenge_url );
        }
        $field         = self::FIELD;
        $worker_inline = $this->argon2id_worker_snippet();

        // Customisation values from the appearance section (Modul 21).
        // Texts fall back to the i18n default when the admin field is empty;
        // colors fall back to the template's hard-coded CSS variable defaults
        // (see under-attack-interstitial.php); custom_css is appended as a
        // second <style> block after the default stylesheet when non-empty.
        // logo_url is an optional image URL rendered above the heading; empty
        // means no logo. Sanitised to a safe URL on save (esc_url_raw).
        $settings  = creationell_captcha_get_settings();
        $texts = [
            'title'    => '' !== trim( (string) ( $settings['underattack_text_title'] ?? '' ) )
                ? (string) $settings['underattack_text_title']
                : __( 'Sicherheitsprüfung', 'creationell-captcha' ),
            'heading'  => '' !== trim( (string) ( $settings['underattack_text_heading'] ?? '' ) )
                ? (string) $settings['underattack_text_heading']
                : __( 'Die Website wird gerade besonders geschützt', 'creationell-captcha' ),
            'message'  => '' !== trim( (string) ( $settings['underattack_text_message'] ?? '' ) )
                ? (string) $settings['underattack_text_message']
                : __( 'Ihr Browser wird kurz geprüft — einen Moment bitte.', 'creationell-captcha' ),
            'noscript' => '' !== trim( (string) ( $settings['underattack_text_noscript'] ?? '' ) )
                ? (string) $settings['underattack_text_noscript']
                : __( 'Für die Sicherheitsprüfung muss JavaScript aktiviert sein.', 'creationell-captcha' ),
        ];
        $colors = [
            'background' => trim( (string) ( $settings['underattack_color_background'] ?? '' ) ),
            'text'       => trim( (string) ( $settings['underattack_color_text']       ?? '' ) ),
        ];
        $user_css = trim( (string) ( $settings['underattack_custom_css'] ?? '' ) );
        $logo_url = trim( (string) ( $settings['underattack_logo_url'] ?? '' ) );

        require CREATIONELL_CAPTCHA_PLUGIN_PATH . 'includes/under-attack-interstitial.php';
        exit;
    }

    /**
     * Returns the inline Argon2id worker-registration script, or '' when the
     * Argon2id algorithm is not in use.
     */
    private function argon2id_worker_snippet(): string {
        $settings = creationell_captcha_get_settings();
        if ( 'argon2id' !== ( $settings['algorithm'] ?? 'pbkdf2' ) || ! creationell_captcha_sodium_available() ) {
            return '';
        }

        $worker_url = CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/altcha-argon2id.worker.js';

        return sprintf(
            'if(window.$altcha&&window.$altcha.algorithms){window.$altcha.algorithms.set("ARGON2ID",function(){return new Worker(%s);});}',
            wp_json_encode( $worker_url )
        );
    }
}
