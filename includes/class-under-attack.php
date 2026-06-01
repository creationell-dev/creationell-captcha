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
        if ( is_string( $solution ) && '' !== $solution
            && creationell_captcha_verify_payload( $solution )
            && $this->issue_pass()
        ) {
            // The visitor solved the challenge and the pass cookie was issued —
            // record the pass so the dashboard can tell "asked" from "passed".
            /** This action is documented in includes/rest.php. */
            do_action( 'creationell_captcha_event', 'underattack_passed', [ 'action' => 'underattack_passed' ] );

            $target = isset( $_SERVER['REQUEST_URI'] )
                ? (string) wp_unslash( $_SERVER['REQUEST_URI'] )
                : '/';
            wp_safe_redirect( $target );
            exit;
        }

        $this->serve_interstitial();
    }

    /**
     * Whether the request carries a valid, unexpired pass token.
     */
    private function has_valid_pass(): bool {
        if ( ! isset( $_COOKIE[ self::COOKIE ] ) ) {
            return false;
        }
        $cookie = (string) wp_unslash( $_COOKIE[ self::COOKIE ] );

        $parts = explode( '.', $cookie, 2 );
        if ( 2 !== count( $parts ) ) {
            return false;
        }
        [ $expiry_raw, $hmac ] = $parts;

        if ( ! ctype_digit( $expiry_raw ) ) {
            return false;
        }

        $expected = hash_hmac( 'sha256', $expiry_raw, creationell_captcha_get_hmac_secret() );
        if ( ! hash_equals( $expected, $hmac ) ) {
            return false;
        }

        return (int) $expiry_raw > time();
    }

    /**
     * Mints a fresh pass token and sets it as a cookie.
     *
     * @return bool True when the cookie was set; false when headers were
     *              already sent and it could not be.
     */
    private function issue_pass(): bool {
        if ( headers_sent() ) {
            return false;
        }

        $settings = creationell_captcha_get_settings();
        $duration = max( 300, min( 86400, (int) ( $settings['underattack_pass_duration'] ?? 3600 ) ) );

        $expiry = time() + $duration;
        $token  = $expiry . '.' . hash_hmac( 'sha256', (string) $expiry, creationell_captcha_get_hmac_secret() );

        setcookie(
            self::COOKIE,
            $token,
            [
                'expires'  => $expiry,
                'path'     => '/',
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]
        );

        return true;
    }

    /**
     * Outputs the interstitial page with HTTP 503 and terminates.
     */
    private function serve_interstitial(): void {
        /** This action is documented in includes/rest.php. */
        do_action( 'creationell_captcha_event', 'underattack', [ 'action' => 'underattack' ] );

        if ( ! headers_sent() ) {
            status_header( 503 );
            nocache_headers();
            header( 'Content-Type: text/html; charset=utf-8' );
        }

        $action        = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
        $widget_src    = CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/altcha.min.js';
        // ?ctx=<hmac> signals the /challenge handler to skip the code-
        // challenge attachment — the interstitial widget is invisible and
        // cannot show a code modal, so a code-challenge here would deadlock
        // the gate. The value is a short-lived HMAC over the current 5-min
        // bucket, so a client cannot forge it; only OUR server-rendered
        // interstitial can hand it to the widget.
        $bucket        = (int) floor( time() / 300 );
        $ctx_token     = hash_hmac( 'sha256', 'ua-ctx|' . $bucket, creationell_captcha_get_hmac_secret() );
        $challenge_url = rest_url( 'creationell-captcha/v1/challenge' ) . '?ctx=' . $ctx_token;
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
