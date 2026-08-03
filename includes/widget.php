<?php
/**
 * Widget rendering, asset loading and request verification.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers the widget script and — for Argon2id — its worker registration.
 */
function creationell_captcha_register_assets(): void {
    if ( creationell_captcha_is_disabled() ) {
        return;
    }

    wp_register_script(
        'creationell-captcha-altcha',
        CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/altcha.min.js',
        [],
        CREATIONELL_CAPTCHA_VERSION,
        true
    );

    // ALTCHA's own base stylesheet — default CSS variables, display-mode
    // positioning (floating/overlay/bar/bottomsheet/invisible) and styling for
    // checkbox/switch/popover/spinner. The UMD JS bundle does not ship CSS;
    // without this file the non-standard display modes have no positioning
    // and the theme attribute has no visual effect.
    wp_register_style(
        'creationell-captcha-altcha-base',
        CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/css/altcha.css',
        [],
        CREATIONELL_CAPTCHA_VERSION
    );

    // Plugin overrides — must load AFTER altcha-base so the
    // --creationell-captcha-primary binding and margin-block-end take
    // precedence over ALTCHA's defaults.
    wp_register_style(
        'creationell-captcha-widget',
        CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/css/widget.css',
        [ 'creationell-captcha-altcha-base' ],
        CREATIONELL_CAPTCHA_VERSION
    );

    $settings = creationell_captcha_get_settings();
    if ( 'argon2id' === ( $settings['algorithm'] ?? 'pbkdf2' ) && creationell_captcha_sodium_available() ) {
        $worker_url = CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/altcha-argon2id.worker.js';
        $inline     = sprintf(
            'if(window.$altcha&&window.$altcha.algorithms){window.$altcha.algorithms.set("ARGON2ID",function(){return new Worker(%s);});}',
            wp_json_encode( $worker_url )
        );
        wp_add_inline_script( 'creationell-captcha-altcha', $inline, 'after' );
    }
}
add_action( 'init', 'creationell_captcha_register_assets' );

/**
 * Macht eine gespeicherte CSS-Zeichenkette sicher für die Ausgabe in einem
 * `<style>`-Element.
 *
 * Gemeinsame Ausgabe-Härtung für beide Stellen, an denen Nutzer-CSS in einen
 * `<style>`-Block geschrieben wird: das Widget (`widget_custom_css`) und die
 * Under-Attack-Interstitial-Seite (`underattack_custom_css`).
 *
 * Warum an der AUSGABE und nicht (nur) im Schreibpfad: Der Sanitizer räumt
 * `widget_custom_css`/`underattack_custom_css` zwar per wp_strip_all_tags() auf,
 * aber mindestens drei Schreibwege erreichen ihn nie — `wp option patch`, fremde
 * `update_option()`-Aufrufe außerhalb des Admin-Kontexts und die eigenen
 * CLI-Befehle `reset`/`load-defaults` (W2 der Befunddatei). Was in der Option
 * steht, ist also nicht garantiert sanitisiert; die Ausgabe muss unabhängig
 * davon sicher sein.
 *
 * @param string $css Rohes CSS aus den Einstellungen.
 * @return string CSS, das den umgebenden `<style>`-Block nicht verlassen kann.
 */
function creationell_captcha_safe_inline_css( string $css ): string {
    // NUL-Bytes zuerst entfernen: HTML-Parser ersetzen U+0000 durch U+FFFD,
    // eine eingestreute 0x00 darf die Erkennung unten also nicht aushebeln.
    $css = str_replace( "\0", '', $css );

    // Ein `<style>`-Element ist RAWTEXT: Es endet ausschließlich an „</" gefolgt
    // vom Tag-Namen. Entfernt wird deshalb jedes „<", das unmittelbar ein Tag
    // eröffnen könnte — „</", „<x", „<!" und „<?". Damit ist der Ausbruch
    // unmöglich, unabhängig vom Inhalt der Option, und im Quelltext bleibt auch
    // keine irreführende Tag-Attrappe stehen.
    //
    // Bewusst NICHT entfernt: „>" (CSS-Kindkombinator `.a > .b`) und ein „<",
    // auf das Leerraum, eine Ziffer oder „=" folgt — das ist die Range-Syntax
    // moderner Media-Queries (`@media (width < 600px)`, `(400px <= width)`).
    // Einzige verbleibende Einbuße: ein „<" direkt vor einem Bezeichner ohne
    // Leerzeichen (`(width <calc(1px))`) verliert das Zeichen.
    $css = (string) preg_replace( '#<(?=[!/?a-zA-Z])#', '', $css );

    return $css;
}

/**
 * Builds the ALTCHA widget markup as a plain string. Enqueues the widget
 * script as a side effect.
 *
 * Safe to call from inside an `ob_start` callback because it does not use
 * output-buffering itself — unlike the legacy `creationell_captcha_get_widget_markup`
 * wrapper that this function now powers.
 *
 * Reads eight widget-customization settings (display, type, auto_trigger,
 * theme, hide_branding, primary_color, custom_css, strings_override) and
 * maps them to the corresponding v3 attributes. Boolean attributes are
 * emitted as empty-string values per HTML5 convention.
 */
function creationell_captcha_build_widget_markup(): string {
    if ( creationell_captcha_is_disabled() ) {
        return '';
    }

    wp_enqueue_script( 'creationell-captcha-altcha' );
    wp_enqueue_style( 'creationell-captcha-altcha-base' );

    $settings = creationell_captcha_get_settings();

    // Theme stylesheet — registered lazily so we only pay for the file the
    // user has actually selected. Whitelist guards against an unexpected
    // setting value sneaking in (sanitize_settings already restricts to the
    // valid options, but this keeps the file-system access defensive).
    $theme        = (string) ( $settings['widget_theme'] ?? 'default' );
    $valid_themes = [ 'aqua', 'business', 'caramel', 'cupcake', 'cyberpunk', 'lime', 'wireframe' ];
    if ( in_array( $theme, $valid_themes, true ) ) {
        $theme_handle = 'creationell-captcha-altcha-theme-' . $theme;
        if ( ! wp_style_is( $theme_handle, 'registered' ) ) {
            wp_register_style(
                $theme_handle,
                CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/css/altcha-themes/' . $theme . '.css',
                [ 'creationell-captcha-altcha-base' ],
                CREATIONELL_CAPTCHA_VERSION
            );
        }
        wp_enqueue_style( $theme_handle );
    }

    // Plugin overrides go last so they win over base and theme.
    wp_enqueue_style( 'creationell-captcha-widget' );

    // Auto-detect widget language from get_locale(). When the WP locale is
    // mapped to a vendored ALTCHA bundle, register that bundle on demand
    // (analogous to the theme stylesheet pattern above) and remember the
    // resolved code so it can be set as the widget's `language` HTML
    // attribute below. Locales without a mapping skip both steps — the
    // widget then runs ALTCHA's own detection from <html lang> /
    // navigator.languages and ultimately falls back to its built-in EN.
    //
    // Normalise an empty string to null — a third-party filter on
    // `creationell_captcha_widget_locale` may legitimately wish to
    // "suppress" the locale; the documented way is to return null, but
    // accept '' too so a buggy filter cannot 404 the page on a missing
    // `assets/js/altcha-i18n/.js`.
    $locale = creationell_captcha_resolve_widget_locale();
    if ( '' === $locale ) {
        $locale = null;
    }
    if ( null !== $locale ) {
        $i18n_handle = 'creationell-captcha-altcha-i18n-' . $locale;
        if ( ! wp_script_is( $i18n_handle, 'registered' ) ) {
            wp_register_script(
                $i18n_handle,
                CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/altcha-i18n/' . $locale . '.js',
                [ 'creationell-captcha-altcha' ],
                CREATIONELL_CAPTCHA_VERSION,
                true
            );
        }
        wp_enqueue_script( $i18n_handle );
    }

    // The <altcha-widget> custom element (npm `altcha` v3) only recognises a
    // fixed set of HTML attributes: auto, challenge, configuration, display,
    // language, name, theme, type, workers. Everything else (verifyUrl,
    // codeChallengeDisplay, floating*, hideFooter, hideLogo, strings, …) must
    // be passed via the `configuration` attribute as a JSON blob.
    //
    // Source: npm package `altcha@3.0.10`, dist/main/altcha.umd.cjs lines
    // 7344-7354 — the customElements.define() prop dictionary.
    $attrs = [
        'challenge' => esc_url( rest_url( 'creationell-captcha/v1/challenge' ) ),
        'name'      => 'altcha',
        'display'   => (string) ( $settings['widget_display'] ?? 'standard' ),
        'type'      => (string) ( $settings['widget_type'] ?? 'checkbox' ),
    ];

    // Set language only when we actually enqueued a matching locale bundle
    // above. The widget treats `language` as an authoritative override of
    // its own auto-detection.
    if ( null !== $locale ) {
        $attrs['language'] = $locale;
    }

    $auto = (string) ( $settings['widget_auto_trigger'] ?? 'none' );
    if ( 'none' !== $auto ) {
        $attrs['auto'] = $auto;
    }

    if ( 'default' !== $theme ) {
        $attrs['theme'] = $theme;
    }

    // All non-recognised props go into the configuration JSON blob.
    //
    // verifyUrl steers the widget into ALTCHA's server-side-verify mode
    // (POST to /code-verify after every solved PoW). Emit it only when the
    // code-challenge feature is actually on — otherwise the widget would
    // hit /code-verify for every plain PoW request and bypass the
    // client-only verify path the widget would normally take. /code-verify
    // does still handle the plain payload-only body shape (defense in
    // depth), but skipping the roundtrip in the common case is the clean
    // default.
    $config = [];
    if ( ! empty( $settings['code_challenge_enabled'] ) ) {
        $config['verifyUrl'] = rest_url( 'creationell-captcha/v1/code-verify' );
    }

    // Floating-Modus-Konfiguration: nur wenn display="floating" gewählt ist
    // und mindestens eine der drei Floating-Optionen vom Default abweicht.
    if ( 'floating' === ( $settings['widget_display'] ?? 'standard' ) ) {
        $anchor = trim( (string) ( $settings['widget_floating_anchor'] ?? '' ) );
        if ( '' !== $anchor ) {
            $config['floatingAnchor'] = $anchor;
        }
        $placement = (string) ( $settings['widget_floating_placement'] ?? 'auto' );
        if ( 'auto' !== $placement ) {
            $config['floatingPlacement'] = $placement;
        }
        $offset = (int) ( $settings['widget_floating_offset'] ?? 12 );
        if ( 12 !== $offset ) {
            $config['floatingOffset'] = $offset;
        }
    }

    // Code-Challenge-Display-Modus.
    $cc_display = (string) ( $settings['widget_code_challenge_display'] ?? 'standard' );
    if ( 'standard' !== $cc_display ) {
        $config['codeChallengeDisplay'] = $cc_display;
    }

    if ( ! empty( $settings['widget_hide_branding'] ) ) {
        $config['hideFooter'] = true;
        $config['hideLogo']   = true;
    }

    $strings_raw = trim( (string) ( $settings['widget_strings_override'] ?? '' ) );
    if ( '' !== $strings_raw ) {
        $parsed = json_decode( $strings_raw, true );
        if ( is_array( $parsed ) ) {
            $config['strings'] = $parsed;
        }
    }

    $config_json = wp_json_encode( $config );
    if ( is_string( $config_json ) ) {
        $attrs['configuration'] = $config_json;
    }

    $html = '<altcha-widget';
    foreach ( $attrs as $key => $value ) {
        $html .= ' ' . esc_attr( $key ) . '="' . esc_attr( $value ) . '"';
    }
    $html .= '></altcha-widget>';
    $html .= '<noscript><div class="creationell-captcha-noscript">'
        . esc_html__( 'Für die Sicherheitsabfrage muss JavaScript aktiviert sein.', 'creationell-captcha' )
        . '</div></noscript>';

    // Inline-<style> für Primary-Color und User-CSS, davor gestellt damit
    // das Widget die Styles vom ersten Render an kennt.
    $inline_css = '';
    $primary    = trim( (string) ( $settings['widget_primary_color'] ?? '' ) );
    if ( '' !== $primary ) {
        $inline_css .= ':root{--creationell-captcha-primary:' . esc_attr( $primary ) . ';}';
    }
    $user_css = trim( (string) ( $settings['widget_custom_css'] ?? '' ) );
    if ( '' !== $user_css ) {
        // AF-2: Härtung an der Ausgabestelle — der Wert in der Option ist nicht
        // garantiert durch den Sanitizer gelaufen (siehe
        // creationell_captcha_safe_inline_css()).
        $inline_css .= creationell_captcha_safe_inline_css( $user_css );
    }
    if ( '' !== $inline_css ) {
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $primary is hex-validated by sanitize_settings (case 'color'), $user_css passed through creationell_captcha_safe_inline_css() above.
        $html = '<style>' . $inline_css . '</style>' . $html;
    }

    return $html;
}

/**
 * Renders the ALTCHA widget markup and enqueues its assets.
 */
function creationell_captcha_render_widget(): void {
    echo creationell_captcha_build_widget_markup(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts in creationell_captcha_build_widget_markup().
}

/**
 * Verifies a raw base64 ALTCHA payload string.
 *
 * Shared by the POST-based request helper and the third-party form
 * integrations, which read the payload from their plugin's submission data.
 *
 * @param string $raw The raw `altcha` payload.
 */
function creationell_captcha_verify_payload( string $raw ): bool {
    if ( creationell_captcha_is_disabled() ) {
        return true;
    }

    if ( '' === $raw ) {
        return false;
    }

    // ALTCHA payloads are base64 — reject anything outside that alphabet early.
    if ( ! preg_match( '#^[A-Za-z0-9+/]+={0,2}$#', $raw ) ) {
        return false;
    }

    return creationell_captcha_engine()->verify( $raw );
}

/**
 * Reads and verifies the ALTCHA payload from the current POST request.
 *
 * The ALTCHA payload itself is the anti-bot token — no separate WordPress
 * nonce applies here.
 */
function creationell_captcha_verify_request(): bool {
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the payload is the token.
    $raw = isset( $_POST['altcha'] ) ? wp_unslash( $_POST['altcha'] ) : '';

    return creationell_captcha_verify_payload( is_string( $raw ) ? $raw : '' );
}

/**
 * Public template tag — renders the ALTCHA widget.
 *
 * For use in theme templates or custom-form markup; the call must sit inside
 * the <form> element so the hidden `altcha` field is submitted with the form.
 */
function creationell_captcha_widget(): void {
    creationell_captcha_render_widget();
}

/**
 * Returns the ALTCHA widget markup as a string.
 *
 * Used by the shortcode and by the third-party form integrations, which embed
 * the widget into another plugin's form markup. Implementation routes through
 * the underlying string builder rather than ob_start so the function is safe
 * to call from inside other output-buffer callbacks (e.g. Modul 12's
 * auto-inject buffer).
 *
 * @return string The widget markup.
 */
function creationell_captcha_get_widget_markup(): string {
    return creationell_captcha_build_widget_markup();
}

/**
 * Shortcode handler for [creationell_captcha].
 *
 * Place the shortcode inside a <form> element so the hidden `altcha` field is
 * submitted with the form.
 *
 * @return string The widget markup.
 */
function creationell_captcha_widget_shortcode(): string {
    return creationell_captcha_get_widget_markup();
}
add_shortcode( 'creationell_captcha', 'creationell_captcha_widget_shortcode' );
