<?php
/**
 * Email-obfuscation bootstrap: content-filter mode and full-page-buffer mode.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers email obfuscation on `init`. The decoder script is always
 * registered; then, unless the kill-switch is set or the feature is off, the
 * configured mode is wired up — the content filters (module 7) or the
 * full-page output buffer (module 8).
 */
function creationell_captcha_register_email_obfuscation(): void {
    wp_register_script(
        'creationell-captcha-email',
        CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/email-obfuscation.js',
        [],
        CREATIONELL_CAPTCHA_VERSION,
        true
    );

    if ( creationell_captcha_is_disabled() ) {
        return;
    }

    $settings = creationell_captcha_get_settings();
    if ( empty( $settings['obfuscate_emails'] ) ) {
        return;
    }

    $obfuscator = new \Creationell\Captcha\EmailObfuscator();

    if ( 'buffer' === ( $settings['obfuscate_emails_mode'] ?? 'content' ) ) {
        creationell_captcha_register_email_buffer( $obfuscator );

        return;
    }

    // Content-filter mode (module 7): the late priority (20) ensures the final
    // HTML — after wpautop, make_clickable and third-party filters — is processed.
    $filters = [ 'the_content', 'the_excerpt', 'widget_text', 'widget_block_content', 'comment_text' ];
    foreach ( $filters as $filter ) {
        add_filter( $filter, [ $obfuscator, 'process' ], 20 );
    }
}
add_action( 'init', 'creationell_captcha_register_email_obfuscation' );

/**
 * Wires up the full-page-buffer mode: on `template_redirect` for non-feed
 * front-end requests it enqueues the decoder script and starts an output
 * buffer whose callback obfuscates the page body at flush time.
 *
 * Der Callback fasst den Puffer nur an, wenn die Antwort HTML ist (EO-5) und
 * eine Größengrenze nicht überschreitet (EO-4). Beides schützt fremde
 * Antworten davor, umgeschrieben zu werden, und verhindert, dass der
 * Obfuskator für eine sehr große Antwort eine zweite Kopie im Speicher
 * aufbaut. Was beides NICHT verhindert: dass PHPs Ausgabepuffer die Antwort
 * überhaupt zwischenspeichert. Ein Handler, der eine große Datei per
 * `readfile()` ausgibt, ohne die offenen Puffer vorher zu leeren, hält sie so
 * oder so komplett im Speicher — das ist eine Eigenschaft von `ob_start()`
 * und trifft jeden Puffer auf der Seite, nicht nur diesen.
 *
 * Kein `creationell_captcha_request_bypassed()` (EO-10, bewusst): Die
 * Obfuskation ist kein Zugangs-Gate, sondern eine Darstellungsänderung — sie
 * lässt niemanden durch und hält niemanden auf. Der Content-Filter-Modus
 * fragt den Bypass ebenso wenig ab; ihn nur hier zu verdrahten, hieße, aus
 * einer Einstellung zwei Verhaltensweisen zu machen, je nach gewähltem Modus.
 * Funktionaler Schaden entsteht nicht: der Decoder stellt die Adresse
 * clientseitig wieder her.
 *
 * @param \Creationell\Captcha\EmailObfuscator $obfuscator The obfuscator.
 */
function creationell_captcha_register_email_buffer( \Creationell\Captcha\EmailObfuscator $obfuscator ): void {
    add_action(
        'template_redirect',
        static function () use ( $obfuscator ): void {
            if ( is_feed() ) {
                return;
            }

            wp_enqueue_script( 'creationell-captcha-email' );

            ob_start(
                static function ( string $html ) use ( $obfuscator ): string {
                    return creationell_captcha_email_buffer_filter( $html, $obfuscator );
                }
            );
        }
    );
}

/**
 * The buffer callback itself: decides whether this response gets rewritten and
 * hands it to the obfuscator when it does.
 *
 * Bewusst eine eigene benannte Funktion statt einer Closure im `ob_start()`:
 * Die beiden Weichen (EO-5 Content-Type, EO-4 Größengrenze) sind der Fix, und
 * ein Test muss sie direkt aufrufen können. In der Closure waren sie nur über
 * einen echten Request erreichbar — der einzige „Nachweis", der dann noch
 * möglich war, prüfte den Default-Wert gegen sich selbst und wäre auch ohne die
 * Weiche grün geblieben.
 *
 * @param string                               $html       Der gepufferte Antwort-Body.
 * @param \Creationell\Captcha\EmailObfuscator $obfuscator The obfuscator.
 * @return string Umgeschriebener oder unveränderter Body.
 */
function creationell_captcha_email_buffer_filter( string $html, \Creationell\Captcha\EmailObfuscator $obfuscator ): string {
    if ( creationell_captcha_is_disabled() ) {
        return $html;
    }
    if ( ! creationell_captcha_response_is_html() ) {
        return $html;
    }

    /**
     * Filters the maximum response size the e-mail obfuscator processes in
     * full-page-buffer mode.
     *
     * Antworten oberhalb der Grenze werden unverändert durchgereicht — ein
     * Datei-Download oder ein sehr großer Export soll nicht zusätzlich eine
     * umgeschriebene Kopie im Speicher erzeugen. Ein Wert <= 0 hebt die Grenze
     * auf.
     *
     * @since 1.1.0
     *
     * @param int $max_bytes Größengrenze in Byte. Default 2 MiB.
     * @param int $actual    Tatsächliche Größe dieser Antwort in Byte.
     */
    $max_bytes = (int) apply_filters(
        'creationell_captcha_email_buffer_max_bytes',
        2 * MB_IN_BYTES,
        strlen( $html )
    );

    if ( $max_bytes > 0 && strlen( $html ) > $max_bytes ) {
        creationell_captcha_log(
            sprintf(
                'email-obfuscation: response of %d bytes exceeds the buffer limit of %d bytes — left unchanged',
                strlen( $html ),
                $max_bytes
            )
        );

        return $html;
    }

    return $obfuscator->process_page( $html );
}

/**
 * Whether the response being buffered is (still) an HTML document.
 *
 * EO-5: `process_page()` prüfte nie den Content-Type. Eine Nicht-HTML-Antwort,
 * die zufällig `<body…>`, `</body>` und ein „@" enthielt — etwa ein von einem
 * Mu-Plugin auf `template_redirect` ausgegebenes JSON mit HTML-Fragment —,
 * wurde umgeschrieben und war danach kaputt.
 *
 * Ein fehlender Content-Type gilt als HTML: `template_redirect` ist der
 * Template-Pfad von WordPress, dessen Antwort per Definition das Theme rendert,
 * und PHPs `default_mimetype` ist `text/html`. Die Prüfung entscheidet
 * ausschließlich darüber, OB umgeschrieben wird — sie ist keine
 * Sicherheitskontrolle, und ein „nein" ist immer die harmlosere Antwort.
 *
 * @return bool
 */
function creationell_captcha_response_is_html(): bool {
    if ( ! function_exists( 'headers_list' ) ) {
        return true;
    }

    $content_type = '';
    foreach ( headers_list() as $header ) {
        if ( 0 === stripos( $header, 'content-type:' ) ) {
            // Der zuletzt gesetzte Header gewinnt — genau wie beim Senden.
            $content_type = strtolower( trim( substr( $header, strlen( 'content-type:' ) ) ) );
        }
    }

    if ( '' === $content_type ) {
        return true;
    }

    return str_starts_with( $content_type, 'text/html' )
        || str_starts_with( $content_type, 'application/xhtml+xml' );
}
