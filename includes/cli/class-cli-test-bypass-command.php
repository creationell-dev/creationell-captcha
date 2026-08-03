<?php
/**
 * WP-CLI: simulates the bypass evaluation with caller-supplied inputs.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha\CLI;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

use WP_CLI;

/**
 * `wp creacaptcha test-bypass`
 */
class Test_Bypass_Command {

    /**
     * Simulates the bypass evaluation with the supplied flag values. Flags are
     * optional — anything not provided is treated as non-matching.
     *
     * Exit code: 0 if the request would be bypassed, 1 otherwise.
     *
     * Was dieses Werkzeug tut — und was nicht (CLI-9): Es ist ein
     * REGEL-SIMULATOR. Die übergebenen Werte werden unverändert gegen die
     * Bypass-Regeln gehalten. Ein echter Request durchläuft vorher
     * `creationell_captcha_get_client_ip()`, das je nach Proxy-Konfiguration
     * eine ANDERE IP ermittelt als die des unmittelbaren Peers. „Kein Bypass"
     * ist deshalb eine Aussage über die Regeln bei DIESER Eingabe, kein Nachweis,
     * dass ein realer Request nicht durchkommt.
     *
     * ## OPTIONS
     *
     * [--ip=<ip>]
     * : IP address (IPv4 or IPv6) to test against the IP allowlist. Wird
     *   unverändert an die Regelprüfung übergeben — siehe die Anmerkung zur
     *   Proxy-Auflösung oben. Eine IPv4-mapped Schreibweise (`::ffff:a.b.c.d`,
     *   wie sie REMOTE_ADDR auf manchen Servern liefert) muss NICHT vorab
     *   umgeschrieben werden: creationell_captcha_ip_in_list() — die einzige
     *   Engstelle, durch die die Erlaubnisliste läuft — kanonisiert das
     *   Subjekt seit 1.1.0 selbst, unabhängig vom Aufrufer.
     *
     * [--ua=<user-agent>]
     * : User-Agent string to test against the UA bypass patterns.
     *
     * [--cookie=<name_value>]
     * : Cookie pair to test against the cookie bypass list (format: name=value).
     *   Mehrere Cookies in EINEM Flag, mit `;` getrennt — WP-CLI wertet bei
     *   mehrfach angegebenem `--cookie` nur das LETZTE aus, die früheren
     *   verschwinden ohne Meldung.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha test-bypass --ip=203.0.113.4
     *     wp creacaptcha test-bypass --ua="Mozilla/5.0"
     *     wp creacaptcha test-bypass --cookie="my_pass=abc"
     *     wp creacaptcha test-bypass --cookie="my_pass=abc; other=xyz"
     *     wp creacaptcha test-bypass --ip=203.0.113.4 --ua="GoogleBot" --cookie="my_pass=abc"
     *
     * @when after_wp_load
     *
     * @param array<int, string>                    $args       Positional arguments.
     * @param array<string, string|array<int,string>> $assoc_args Associative arguments.
     */
    public function __invoke( array $args, array $assoc_args ): void {
        $ip = isset( $assoc_args['ip'] ) ? (string) $assoc_args['ip'] : null;
        $ua = isset( $assoc_args['ua'] ) ? (string) $assoc_args['ua'] : null;

        $cookies     = [];
        $cookie_args = $assoc_args['cookie'] ?? [];
        // CLI-8: `--cookie` ist NICHT wiederholbar und wird auch nicht als
        // wiederholbar deklariert. WP-CLI baut die assoc-Argumente in
        // Configurator::unmix_assoc_args() mit `$assoc_args[$key] = $value`
        // auf — bei mehrfachem `--cookie=` überlebt nur das letzte, unabhängig
        // von der Synopsis. Ein `...` im Synopsis-Token würde die Hilfe zu
        // einem Versprechen machen, das die Laufzeit nicht hält. Stattdessen:
        // ein Flag, mehrere Paare per `;` — dieselbe Trennung, die auch ein
        // echter Cookie-Header verwendet. Der Array-Zweig bleibt für Aufrufer
        // über WP_CLI::run_command(), die assoc-Argumente direkt als Array
        // übergeben und den Zeichenketten-Parser gar nicht durchlaufen.
        if ( ! is_array( $cookie_args ) ) {
            $cookie_args = explode( ';', (string) $cookie_args );
        }
        foreach ( $cookie_args as $raw ) {
            $raw = trim( (string) $raw );
            if ( '' === $raw ) {
                continue;
            }
            $pos = strpos( $raw, '=' );
            if ( false === $pos ) {
                WP_CLI::warning( sprintf( 'Cookie-Wert „%s" ignoriert (erwartet: name=value).', $raw ) );
                continue;
            }
            $name  = trim( substr( $raw, 0, $pos ) );
            $value = substr( $raw, $pos + 1 );
            // B-M22: PHP populates $_COOKIE with the URL-DECODED value — the real
            // request path (creationell_captcha_request_bypassed(), helpers.php)
            // compares against that decoded form, never against the raw header
            // bytes. Without decoding here, an entry with an encoded character
            // (e.g. `--cookie="my_pass=hallo%20welt"`, meant to represent the
            // value a browser would send for `hallo welt`) was compared literally
            // and reported "kein Bypass" for a value a real request WOULD pass —
            // the same "diagnosis answers a different question than it checks"
            // class as the seven already-fixed doctor findings (Bündel 5).
            $cookies[ $name ] = urldecode( $value );
        }

        $result = creationell_captcha_evaluate_bypass( $ip, $ua, $cookies );

        if ( false === $result ) {
            WP_CLI::log( 'Kein Bypass — keine Regel hat bei DIESER Eingabe getroffen.' );
            $this->note_ip_resolution_gap( $ip );
            WP_CLI::halt( 1 );
        }

        WP_CLI::success(
            sprintf(
                'Würde bypasst werden — Quelle: %s (matched: %s).',
                $result['reason'],
                $result['source']
            )
        );
    }

    /**
     * Points out that `--ip` skips the client-IP resolution a real request goes
     * through — but only when the site is actually configured to resolve a
     * forwarded IP, because only then can simulation and reality diverge.
     *
     * @param string|null $ip The value passed as `--ip`, or null.
     */
    private function note_ip_resolution_gap( ?string $ip ): void {
        if ( null === $ip ) {
            return;
        }

        $settings = creationell_captcha_get_settings();
        if ( empty( $settings['firewall_behind_proxy'] ) ) {
            return;
        }

        WP_CLI::log(
            sprintf(
                'Hinweis: Der Proxy-Modus ist aktiv (Header „%s"). Bei einem echten Request entscheidet nicht der hier übergebene Wert, sondern die von creationell_captcha_get_client_ip() ermittelte Adresse — bei vertrauenswürdigem Peer also der Header-Wert des Clients. Dieses Ergebnis gilt für „%s" als Client-IP, nicht für einen Request von dieser Adresse.',
                (string) ( $settings['firewall_proxy_header'] ?? 'x-forwarded-for' ),
                $ip
            )
        );
    }
}
