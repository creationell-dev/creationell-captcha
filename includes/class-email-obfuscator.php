<?php
/**
 * Email obfuscation — hides addresses from spam harvesters.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Obfuscates mailto: links and plain-text email addresses in front-end
 * output. The real address is XOR-hex encoded into a data-cce attribute and
 * restored client-side by the decoder script. Two modes share this class: the
 * content-filter mode (process()) and the full-page-buffer mode
 * (process_page()). See the module-7 and module-8 design specs.
 */
class EmailObfuscator {

    /**
     * Content-filter callback. Returns the content unchanged when the feature
     * is off or the context is admin/feed; otherwise obfuscates addresses and
     * enqueues the decoder script.
     *
     * @param mixed $content The content passed by the WordPress filter.
     * @return string
     */
    public function process( $content ): string {
        $content = is_string( $content ) ? $content : '';

        if ( creationell_captcha_is_disabled() ) {
            return $content;
        }
        if ( empty( creationell_captcha_get_settings()['obfuscate_emails'] ) ) {
            return $content;
        }
        if ( is_admin() || is_feed() ) {
            return $content;
        }

        $result = $this->obfuscate( $content );
        if ( $result !== $content ) {
            wp_enqueue_script( 'creationell-captcha-email' );
        }

        return $result;
    }

    /**
     * Full-page-buffer entry — obfuscates addresses inside the page <body>.
     *
     * The <head> and everything outside <body> is left untouched. Returns the
     * HTML unchanged when no <body> is present (e.g. a non-HTML response).
     *
     * @param string $html The full buffered page HTML.
     * @return string
     */
    public function process_page( string $html ): string {
        if ( ! str_contains( $html, '@' ) ) {
            return $html;
        }

        $result = preg_replace_callback(
            '#(<body\b[^>]*>)(.*)(</body>)#is',
            function ( array $m ): string {
                return $m[1] . $this->obfuscate( $m[2] ) . $m[3];
            },
            $html,
            1
        );

        return is_string( $result ) ? $result : $html;
    }

    /**
     * The shared, script-safe obfuscation pass. Tokenises the HTML once, then
     * encodes `mailto:` hrefs in tag segments and plain-text addresses in text
     * segments; <script> and <style> blocks are skipped in both passes.
     *
     * @param string $html The HTML to process.
     * @return string
     */
    private function obfuscate( string $html ): string {
        if ( ! str_contains( $html, '@' ) ) {
            return $html;
        }

        // Split into text/tag segments; the tag pattern accounts for quoted
        // attribute values so a ">" inside an attribute does not end a tag early.
        $parts = preg_split( '#(<(?:[^>"\']+|"[^"]*"|\'[^\']*\')*>)#', $html, -1, PREG_SPLIT_DELIM_CAPTURE );
        if ( ! is_array( $parts ) ) {
            return $html;
        }

        $placeholder = esc_html__( '[E-Mail-Adresse — bitte JavaScript aktivieren]', 'creationell-captcha' );
        $skip        = false;

        foreach ( $parts as $i => $part ) {
            if ( 1 === $i % 2 ) {
                // Tag segment — track <script>/<style> regions, encode mailto hrefs.
                if ( preg_match( '#^<\s*(script|style)\b#i', $part ) ) {
                    $skip = true;
                } elseif ( preg_match( '#^<\s*/\s*(script|style)\s*>#i', $part ) ) {
                    $skip = false;
                }
                if ( $skip || ! str_contains( $part, '@' ) ) {
                    continue;
                }
                $encoded = preg_replace_callback(
                    '#href=(["\'])mailto:([^"\']+)\1#i',
                    function ( array $m ): string {
                        return 'href="#" data-cce="' . $this->encode( $m[2] ) . '"';
                    },
                    $part
                );
                if ( is_string( $encoded ) ) {
                    $parts[ $i ] = $encoded;
                }
                continue;
            }

            // Text segment — encode plain-text addresses.
            if ( $skip || '' === $part || ! str_contains( $part, '@' ) ) {
                continue;
            }
            $replaced = preg_replace_callback(
                '#[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}#',
                function ( array $m ) use ( $placeholder ): string {
                    return '<span data-cce="' . $this->encode( $m[0] ) . '">' . $placeholder . '</span>';
                },
                $part
            );
            if ( is_string( $replaced ) ) {
                $parts[ $i ] = $replaced;
            }
        }

        return implode( '', $parts );
    }

    /**
     * XOR-hex encodes a string: a random key byte followed by each byte of the
     * value XOR-ed with that key, all two-digit hex. The result contains no
     * "@" and no recognisable email structure.
     *
     * @param string $value The value to encode.
     * @return string
     */
    private function encode( string $value ): string {
        $key = random_int( 0, 255 );
        $hex = sprintf( '%02x', $key );
        $len = strlen( $value );
        for ( $i = 0; $i < $len; $i++ ) {
            $hex .= sprintf( '%02x', ord( $value[ $i ] ) ^ $key );
        }

        return $hex;
    }
}
