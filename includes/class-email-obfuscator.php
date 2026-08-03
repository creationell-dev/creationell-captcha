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
 *
 * Was NICHT erfasst wird (EO-7, bewusste Grenze): Eine Adresse, die im Quelltext
 * kein literales „@" enthält — `info&#64;example.com`, `info&#x40;example.com`,
 * `info&commat;example.com` —, bleibt unverändert. Solche Schreibweisen sind
 * bereits eine Obfuskation des Autors; sie hier aufzulösen hieße, den gesamten
 * Text durch eine Entity-Dekodierung zu schicken und danach wieder korrekt zu
 * kodieren, mit deutlich mehr Möglichkeiten, fremdes Markup zu beschädigen, als
 * der Gewinn rechtfertigt. Der Fall ist fail-open: die Adresse bleibt sichtbar,
 * die Seite intakt.
 */
class EmailObfuscator {

    /**
     * Elements whose content is never rewritten.
     *
     * `script`/`style`/`textarea` sind im HTML-Parser Raw-Text- bzw.
     * RCDATA-Elemente: ein „<" in ihrem Inhalt beginnt dort kein Tag. Genau das
     * bildet der Scanner nach — er überspringt bis zum passenden Schluss-Tag.
     * `template` steht aus einem anderen Grund hier: sein Inhalt ist eine
     * Vorlage, die der Decoder nie erreicht (`querySelectorAll()` greift nicht
     * in ein Template-Fragment), ein `<span data-cce>` darin bliebe also für
     * immer der Platzhaltertext (EO-3).
     *
     * `noscript` gehört NICHT hierher, obwohl es bei aktivem Scripting
     * ebenfalls Raw-Text ist. Die Überlegung „der Platzhalter wäre dort
     * sichtbarer Quelltext" trägt für dieses Element nicht:
     *
     *   - Ist JavaScript AN, stellt der Browser den `<noscript>`-Block gar
     *     nicht dar — ob dort eine Adresse oder ein Platzhalter steht, sieht
     *     niemand.
     *   - Ist JavaScript AUS, wird der Block dargestellt, der Decoder läuft
     *     aber nie. Dann ist der Platzhaltertext „[E-Mail-Adresse — bitte
     *     JavaScript aktivieren]" genau die richtige Anzeige.
     *
     * In beiden Fällen ist der einzige messbare Unterschied, dass die Adresse
     * ohne Obfuskation im ausgelieferten Quelltext steht — dort, wo ein
     * Adress-Sammler liest. `noscript` auf der Skip-Liste war deshalb ein
     * Deckungsverlust gegenüber dem Vorgängerstand (B-M1).
     *
     * Grenze: Übersprungen wird bis zum ERSTEN passenden Schluss-Tag. Bei einem
     * `<template>` in einem `<template>` endet der übersprungene Bereich damit
     * am inneren `</template>`.
     */
    private const SKIP_ELEMENTS = [ 'script', 'style', 'textarea', 'template' ];

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

        $result = $this->obfuscate( $content, false );
        if ( $result !== $content ) {
            wp_enqueue_script( 'creationell-captcha-email' );
        }

        return $result;
    }

    /**
     * Full-page-buffer entry — obfuscates addresses inside the page <body>.
     *
     * Everything before the opening `<body>` tag and everything after the
     * closing `</body>` tag is copied through byte for byte; ohne `<body>`-Tag
     * bleibt das Dokument unverändert.
     *
     * Diese Methode ist eine reine Zeichenketten-Transformation und prüft NICHT,
     * ob die Antwort überhaupt HTML ist oder wie groß sie ist — das entscheidet
     * der Aufrufer, bevor er sie überhaupt ruft (siehe
     * `creationell_captcha_register_email_buffer()` in email-obfuscation.php,
     * EO-4/EO-5).
     *
     * @param string $html The full buffered page HTML.
     * @return string
     */
    public function process_page( string $html ): string {
        return $this->obfuscate( $html, true );
    }

    /**
     * The shared, markup-aware obfuscation pass.
     *
     * Läuft die Zeichenkette einmal linear durch und unterscheidet dabei
     * Text, Tag, Kommentar und Raw-Text-Bereich — so, wie ein HTML-Parser die
     * Grenzen zieht.
     *
     * Genauer, damit die Zusicherung nicht mehr verspricht als sie hält: Der
     * Scanner bildet die Zustandsübergänge des HTML-Tokenizers nach, die über
     * die GRENZEN entscheiden (beginnt hier ein Tag? wo endet es? was ist
     * Raw-Text?). Er ist kein Parser: er baut keinen Baum, kennt keine
     * impliziten Schluss-Tags und keine Verschachtelung. An genau EINER Stelle
     * weicht er vom Tokenizer bewusst ab und begründet das dort: bei einem
     * quotierten Attributwert, der nie schließt (`markup_end()`).
     *
     * Der Vorgänger zerlegte die Eingabe mit
     * `preg_split( '#(<(?:[^>"\']+|"[^"]*"|\'[^\']*\')*>)#' )` und ging davon
     * aus, dass jedes „<" ein Tag beginnt. Ein rohes „<" im Text (`a < b`,
     * `i<n` in Inline-JS) fraß deshalb alles bis zum nächsten „>" — samt eines
     * dazwischenliegenden `<script>` (EO-2: der Skript-Rumpf lief anschließend
     * als Textsegment durch den Klartext-Regex, was ein JS-Stringliteral
     * zerbrach und einen echten SyntaxError erzeugte) oder samt des echten
     * `</script>` (EO-1: `$skip` hing, die Obfuskation blieb für den Rest des
     * Blocks aus). Hier entscheidet stattdessen das Zeichen NACH dem „<", ob
     * überhaupt Markup beginnt; alles andere ist Text und wird als Text
     * behandelt.
     *
     * @param string $html      The HTML to process.
     * @param bool   $body_only Nur den Inhalt zwischen `<body>` und `</body>`
     *                          umschreiben (Buffer-Modus).
     * @return string
     */
    private function obfuscate( string $html, bool $body_only ): string {
        if ( ! str_contains( $html, '@' ) ) {
            return $html;
        }

        $placeholder = esc_html__( '[E-Mail-Adresse — bitte JavaScript aktivieren]', 'creationell-captcha' );
        $len         = strlen( $html );
        $pos         = 0;
        $out         = '';

        // Im Buffer-Modus wird erst ab dem echten <body>-Tag umgeschrieben.
        // EO-6: Der frühere greedy `#(<body\b[^>]*>)(.*)(</body>)#is` ankerte auf
        // das ERSTE Vorkommen von „<body" im Dokument — auch auf eines in einem
        // Skript-Stringliteral im <head>, womit der Head-Inhalt mitverarbeitet
        // wurde, entgegen der Zusicherung des Docblocks. Der Scanner sieht ein
        // „<body" in einem <script>-Block gar nicht erst, weil er den Block als
        // Raw-Text überspringt.
        $active = ! $body_only;

        while ( $pos < $len ) {
            $lt = strpos( $html, '<', $pos );

            if ( false === $lt ) {
                $out .= $this->encode_text( substr( $html, $pos ), $active, $placeholder );
                break;
            }
            if ( $lt > $pos ) {
                $out .= $this->encode_text( substr( $html, $pos, $lt - $pos ), $active, $placeholder );
            }

            // Kommentar: unverändert übernehmen. Bleibt er unabgeschlossen, ist
            // der Rest des Dokuments für einen Parser ebenfalls Kommentar.
            if ( 0 === substr_compare( $html, '<!--', $lt, 4 ) ) {
                $end  = strpos( $html, '-->', $lt + 4 );
                $end  = ( false === $end ) ? $len : $end + 3;
                $out .= substr( $html, $lt, $end - $lt );
                $pos  = $end;
                continue;
            }

            $tag_end = $this->markup_end( $html, $lt );
            if ( null === $tag_end ) {
                // Ein „<", das kein Markup beginnt (EO-1/EO-2). Es ist Text und
                // bleibt Text — der Scanner sucht nicht nach einem „>".
                $out .= '<';
                $pos  = $lt + 1;
                continue;
            }

            $tag     = substr( $html, $lt, $tag_end - $lt );
            $name    = $this->element_name( $tag );
            $closing = str_starts_with( $tag, '</' );

            if ( $body_only && 'body' === $name ) {
                if ( ! $closing ) {
                    $out   .= $tag;
                    $pos    = $tag_end;
                    $active = true;
                    continue;
                }
                // Ab dem </body> wird nichts mehr angefasst.
                $out .= substr( $html, $lt );
                return $out;
            }

            $out .= $active ? $this->encode_tag( $tag ) : $tag;
            $pos  = $tag_end;

            if ( ! $closing && in_array( $name, self::SKIP_ELEMENTS, true ) ) {
                $skip_end = $this->raw_text_end( $html, $name, $pos );
                $out     .= substr( $html, $pos, $skip_end - $pos );
                $pos      = $skip_end;
            }
        }

        return $out;
    }

    /**
     * Where the markup starting at `$lt` ends — or NULL when no markup starts
     * there and the `<` is literal text.
     *
     * Die Unterscheidung folgt der HTML-Tokenizer-Regel: nach „<" beginnt ein
     * Tag nur bei einem Buchstaben, nach „</" ebenfalls nur bei einem
     * Buchstaben; „<!" und „<?" leiten Deklaration bzw.
     * Verarbeitungsanweisung ein. Alles andere („< b", „<3", „<=") ist Text.
     *
     * Ein Anführungszeichen begrenzt einen Attributwert NUR unmittelbar nach
     * dem „=" (Leerzeichen dazwischen erlaubt) — genau wie im HTML-Tokenizer,
     * der aus dem „attribute value (unquoted) state" nicht mehr in einen
     * Quoted-Value-State wechselt. Eine frühere Fassung nahm jedes „'" und
     * jedes „\"" im Tag als Wertbeginn; ein Apostroph in einem UNQUOTETEN Wert
     * (`<p title=don't>`) öffnete damit einen Bereich, der nie schloss, die
     * Schleife lief bis zum Dokumentende und der gesamte Rest wurde als EIN Tag
     * unverändert durchgereicht — die Obfuskation fiel ab dieser Stelle
     * ersatzlos aus, in beiden Modi und ohne Meldung.
     *
     * @param string $html Full document.
     * @param int    $lt   Offset of the `<`.
     * @return int|null Offset just past the closing `>`, or NULL for literal text.
     */
    private function markup_end( string $html, int $lt ): ?int {
        $len  = strlen( $html );
        $next = $html[ $lt + 1 ] ?? '';

        $is_markup = ( '' !== $next )
            && (
                ctype_alpha( $next )
                || '!' === $next
                || '?' === $next
                || ( '/' === $next && ctype_alpha( $html[ $lt + 2 ] ?? '' ) )
            );

        if ( ! $is_markup ) {
            return null;
        }

        $quote        = '';
        $after_equals = false;
        $first_gt     = -1;

        for ( $i = $lt + 1; $i < $len; $i++ ) {
            $char = $html[ $i ];

            // Erstes „>" überhaupt — die Notbremse unten, falls ein quotierter
            // Wert nie schließt.
            if ( '>' === $char && -1 === $first_gt ) {
                $first_gt = $i;
            }

            if ( '' !== $quote ) {
                if ( $char === $quote ) {
                    $quote = '';
                }
                continue;
            }
            if ( '>' === $char ) {
                return $i + 1;
            }
            if ( '=' === $char ) {
                $after_equals = true;
                continue;
            }
            if ( $after_equals ) {
                if ( '"' === $char || "'" === $char ) {
                    $quote        = $char;
                    $after_equals = false;
                    continue;
                }
                // Ab dem ersten Nicht-Leerzeichen läuft ein unquoteter Wert;
                // ein Anführungszeichen darin ist ein gewöhnliches Zeichen.
                if ( ! $this->is_html_space( $char ) ) {
                    $after_equals = false;
                }
            }
        }

        // Kein abschließendes „>" gefunden. Zwei Fälle:
        //
        // a) Es gibt überhaupt kein „>" mehr (`<div class="x` am Dokumentende).
        //    Dann verschluckt auch ein Parser den Rest; er wird unverändert
        //    übernommen.
        // b) Ein quotierter Wert schließt nie, obwohl danach noch „>" folgen
        //    (`<a href="/x> … `). Ein Parser verwirft hier ebenfalls den Rest
        //    des Dokuments — HIER WIRD BEWUSST ABGEWICHEN und am ersten „>"
        //    abgeschnitten. Grund: Der Browser zeigt den Rest zwar nicht an,
        //    im ausgelieferten Quelltext steht er aber weiterhin, und genau den
        //    liest ein Adress-Sammler. Ein einzelnes kaputtes Tag darf die
        //    Obfuskation nicht für den gesamten Rest des Dokuments abschalten.
        if ( -1 !== $first_gt ) {
            return $first_gt + 1;
        }

        return $len;
    }

    /**
     * Lower-cased element name of a start or end tag; '' for declarations.
     *
     * @param string $tag Full tag including the angle brackets.
     */
    private function element_name( string $tag ): string {
        if ( 1 === preg_match( '#^</?([A-Za-z][A-Za-z0-9-]*)#', $tag, $matches ) ) {
            return strtolower( $matches[1] );
        }

        return '';
    }

    /**
     * Offset of the `<` of the closing tag for a raw-text element, or the end
     * of the document when it never closes.
     *
     * @param string $html Full document.
     * @param string $name Lower-cased element name.
     * @param int    $from Offset just past the opening tag.
     */
    private function raw_text_end( string $html, string $name, int $from ): int {
        $len    = strlen( $html );
        $needle = '</' . $name;
        $offset = $from;

        while ( $offset < $len ) {
            $candidate = stripos( $html, $needle, $offset );
            if ( false === $candidate ) {
                return $len;
            }

            // `</scriptable>` schließt kein `<script>` — nach dem Namen muss ein
            // Tag-Ende oder ein Trennzeichen folgen.
            $after = $html[ $candidate + strlen( $needle ) ] ?? '>';
            if ( in_array( $after, [ '>', '/', ' ', "\t", "\n", "\r", "\f" ], true ) ) {
                return $candidate;
            }

            $offset = $candidate + 1;
        }

        return $len;
    }

    /**
     * Encodes plain-text addresses in a text segment.
     *
     * @param string $text        The text segment.
     * @param bool   $active      Whether rewriting is switched on here.
     * @param string $placeholder Visible replacement text.
     */
    private function encode_text( string $text, bool $active, string $placeholder ): string {
        if ( ! $active || '' === $text || ! str_contains( $text, '@' ) ) {
            return $text;
        }

        $replaced = preg_replace_callback(
            '#[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}#',
            function ( array $m ) use ( $placeholder ): string {
                return '<span data-cce="' . $this->encode( $m[0] ) . '">' . $placeholder . '</span>';
            },
            $text
        );

        return is_string( $replaced ) ? $replaced : $text;
    }

    /**
     * Encodes a `mailto:` href inside a single start tag.
     *
     * EO-7: Der Vorgänger-Regex verlangte ein Anführungszeichenpaar und ließ
     * `<a href=mailto:info@example.com>` unverändert. Unquotete Attributwerte
     * sind unüblich, aber gültiges HTML.
     *
     * Warum das Tag hier attributweise durchlaufen und nicht einfach der Regex
     * um eine unquotete Alternative erweitert wird: Ein Muster, das
     * `href=mailto:…` irgendwo im Tag sucht, trifft auch die Zeichenfolge
     * `href=mailto:` INNERHALB eines anderen Attributwerts
     * (`<a data-original="href=mailto:x@y.de">`) und würde dort mitten in den
     * Wert ein zweites Anführungszeichen schreiben — aus einem
     * Darstellungsproblem würde kaputtes Markup. Der Durchlauf weiß, wo ein
     * Attributname steht und wo ein Wert, und ersetzt nur echte href-Attribute.
     *
     * @param string $tag Full tag including the angle brackets.
     */
    private function encode_tag( string $tag ): string {
        // Schluss-Tags und Deklarationen tragen keine Attribute.
        if ( ! str_contains( $tag, '@' ) || 1 !== preg_match( '#^<[A-Za-z]#', $tag ) ) {
            return $tag;
        }

        $len = strlen( $tag );

        // Elementname überspringen.
        $i = 1;
        while ( $i < $len && ! $this->is_html_space( $tag[ $i ] ) && '>' !== $tag[ $i ] && '/' !== $tag[ $i ] ) {
            ++$i;
        }
        $out = substr( $tag, 0, $i );

        while ( $i < $len ) {
            // Trennendes Leerzeichen bzw. ein „/" vor dem nächsten Attribut.
            $gap = $i;
            while ( $i < $len && ( $this->is_html_space( $tag[ $i ] ) || '/' === $tag[ $i ] ) ) {
                ++$i;
            }
            $out .= substr( $tag, $gap, $i - $gap );

            if ( $i >= $len ) {
                break;
            }
            if ( '>' === $tag[ $i ] ) {
                $out .= substr( $tag, $i );
                break;
            }

            // Attributname.
            $name_start = $i;
            while ( $i < $len && ! $this->is_html_space( $tag[ $i ] ) && '=' !== $tag[ $i ] && '>' !== $tag[ $i ] && '/' !== $tag[ $i ] ) {
                ++$i;
            }
            if ( $i === $name_start ) {
                // Kein Name konsumiert (z. B. ein führendes „=" in kaputtem
                // Markup). Ein Zeichen übernehmen und weiter — ohne diesen
                // Schritt stünde die Schleife still.
                $out .= $tag[ $i ];
                ++$i;
                continue;
            }
            $name       = strtolower( substr( $tag, $name_start, $i - $name_start ) );
            $after_name = $i;

            // Optionales „=" samt Wert.
            while ( $i < $len && $this->is_html_space( $tag[ $i ] ) ) {
                ++$i;
            }
            if ( $i >= $len || '=' !== $tag[ $i ] ) {
                // Attribut ohne Wert.
                $out .= substr( $tag, $name_start, $after_name - $name_start );
                $i    = $after_name;
                continue;
            }
            ++$i;
            while ( $i < $len && $this->is_html_space( $tag[ $i ] ) ) {
                ++$i;
            }

            if ( $i < $len && ( '"' === $tag[ $i ] || "'" === $tag[ $i ] ) ) {
                $quote       = $tag[ $i ];
                $value_start = ++$i;
                while ( $i < $len && $tag[ $i ] !== $quote ) {
                    ++$i;
                }
                $value = substr( $tag, $value_start, $i - $value_start );
                if ( $i < $len ) {
                    ++$i;
                }
            } else {
                $value_start = $i;
                while ( $i < $len && ! $this->is_html_space( $tag[ $i ] ) && '>' !== $tag[ $i ] ) {
                    ++$i;
                }
                $value = substr( $tag, $value_start, $i - $value_start );
            }

            if ( 'href' === $name && 1 === preg_match( '#^mailto:(.+)$#is', $value, $matches ) ) {
                $out .= 'href="#" data-cce="' . $this->encode( $matches[1] ) . '"';
                continue;
            }

            $out .= substr( $tag, $name_start, $i - $name_start );
        }

        return $out;
    }

    /**
     * Whether the byte is HTML whitespace (space, tab, LF, FF, CR).
     *
     * @param string $char Single byte.
     */
    private function is_html_space( string $char ): bool {
        return ' ' === $char || "\t" === $char || "\n" === $char || "\f" === $char || "\r" === $char;
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
