<?php
/**
 * Reusable WP-CLI command for a single list-type setting.
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
 * Manages one list-type setting — IP block/allow list, UA block list or the
 * interceptor path list. The same class backs the blocklist, allowlist,
 * ua-blocklist and paths command namespaces.
 */
class List_Command {

    /**
     * The list setting key this instance manages.
     */
    private string $key;

    /**
     * Validation type: 'ip' (IP/CIDR), 'action' (action-slug charset),
     * 'cookie' (name=value), or 'text' (plain).
     */
    private string $validation;

    /**
     * @param string $key        The list setting key.
     * @param string $validation 'ip' (IP/CIDR), 'action' (action slug),
     *                           'cookie' (name=value), or 'text' (plain).
     */
    public function __construct( string $key, string $validation = 'text' ) {
        $this->key        = $key;
        $this->validation = $validation;
    }

    /**
     * Adds one or more entries to the list.
     *
     * Nach dem Schreiben wird die Liste erneut gelesen und mit der Absicht
     * verglichen. Exit-Code 1, wenn mindestens ein Eingabewert abgelehnt wurde
     * (ungültig oder Liste voll) oder wenn ein Eintrag beim Speichern verworfen
     * wurde; Exit-Code 0 nur, wenn jeder angenommene Eintrag danach wirklich in
     * der Liste steht.
     *
     * ## OPTIONS
     *
     * <entry>...
     * : One or more entries to add.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist add 203.0.113.4 203.0.113.0/24
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function add( $args, $assoc_args ): void {
        $before   = $this->current();
        $list     = $before;
        $intended = [];
        $rejected = 0;
        $full     = false;

        foreach ( $args as $raw ) {
            if ( $full ) {
                ++$rejected;
                continue;
            }
            $entry = $this->normalise( (string) $raw );
            if ( null === $entry ) {
                WP_CLI::warning( sprintf( '„%s" wurde nicht hinzugefügt — %s', $raw, $this->reject_reason( (string) $raw ) ) );
                ++$rejected;
                continue;
            }
            if ( in_array( $entry, $list, true ) ) {
                WP_CLI::log( sprintf( '„%s" ist bereits enthalten.', $entry ) );
                continue;
            }
            if ( count( $list ) >= 50 ) {
                WP_CLI::warning( 'Die Liste ist voll (maximal 50 Einträge) — weitere Einträge wurden nicht hinzugefügt.' );
                $full = true;
                ++$rejected;
                continue;
            }
            $list[]     = $entry;
            $intended[] = $entry;
        }

        if ( empty( $intended ) ) {
            // CLI-2: Ohne Schreibvorgang gibt es nichts zu verifizieren — aber
            // der Exit-Code muss trotzdem zwischen „nichts zu tun" und
            // „Eingabe abgelehnt" unterscheiden.
            if ( $rejected > 0 ) {
                WP_CLI::error( sprintf( '%d Eingabewert(e) abgelehnt, kein Eintrag hinzugefügt.', $rejected ) );
            }
            WP_CLI::success( '0 Eintrag/Einträge hinzugefügt (nichts Neues).' );
            return;
        }

        $stored = $this->save( $list );
        $this->report_collateral_drops( $before, $stored );

        // CLI-1/CLI-2: Der eigentliche Fix ist diese Rückprüfung. Bisher meldete
        // add() „%d Eintrag hinzugefügt", sobald die CLI-eigene Validierung den
        // Wert durchgelassen hatte — ob der Sanitizer ihn beim Speichern wieder
        // verwarf (Präfixlänge 0, requires-Gate, Längen-/Mengengrenzen), sah der
        // Aufrufer nicht. Gemeldet wird jetzt der tatsächlich gespeicherte Stand,
        // nicht die Absicht.
        $missing = array_values( array_diff( $intended, $stored ) );
        if ( ! empty( $missing ) ) {
            WP_CLI::error(
                sprintf(
                    '%d von %d Einträgen steht nach dem Speichern NICHT in „%s": %s. Der Wert wurde beim Schreiben verworfen.',
                    count( $missing ),
                    count( $intended ),
                    $this->key,
                    implode( ', ', $missing )
                )
            );
        }

        if ( $rejected > 0 ) {
            WP_CLI::error(
                sprintf(
                    '%d Eintrag/Einträge hinzugefügt, %d Eingabewert(e) abgelehnt (siehe Warnungen oben).',
                    count( $intended ),
                    $rejected
                )
            );
        }

        WP_CLI::success( sprintf( '%d Eintrag/Einträge hinzugefügt.', count( $intended ) ) );
    }

    /**
     * Removes one or more entries from the list.
     *
     * Exit-Code 1, wenn ein zu entfernender Eintrag nach dem Schreiben noch in
     * der Liste steht. Ein Eintrag, der gar nicht in der Liste war, ist kein
     * Fehler (unverändertes Verhalten).
     *
     * ## OPTIONS
     *
     * <entry>...
     * : One or more entries to remove.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist remove 203.0.113.4
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function remove( $args, $assoc_args ): void {
        $before  = $this->current();
        $list    = $before;
        $removed = [];

        foreach ( $args as $raw ) {
            $entry = trim( (string) $raw );
            $index = array_search( $entry, $list, true );
            if ( false === $index ) {
                WP_CLI::log( sprintf( '„%s" war nicht in der Liste.', $entry ) );
                continue;
            }
            unset( $list[ $index ] );
            $removed[] = $entry;
        }

        if ( empty( $removed ) ) {
            WP_CLI::success( '0 Eintrag/Einträge entfernt.' );
            return;
        }

        $stored = $this->save( array_values( $list ) );
        $this->report_collateral_drops( $before, $stored, $removed );

        // CLI-2: Wie bei add() zählt der gespeicherte Stand, nicht die Absicht.
        $survivors = array_values( array_intersect( $removed, $stored ) );
        if ( ! empty( $survivors ) ) {
            WP_CLI::error(
                sprintf(
                    '%d Eintrag/Einträge steht/stehen nach dem Speichern weiterhin in „%s": %s.',
                    count( $survivors ),
                    $this->key,
                    implode( ', ', $survivors )
                )
            );
        }

        WP_CLI::success( sprintf( '%d Eintrag/Einträge entfernt.', count( $removed ) ) );
    }

    /**
     * Prints the current list entries.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist list
     *
     * @subcommand list
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function list_entries( $args, $assoc_args ): void {
        $format = $assoc_args['format'] ?? 'table';

        $rows = [];
        foreach ( $this->current() as $entry ) {
            $rows[] = [ 'eintrag' => $entry ];
        }

        // B-M22: eine leere Liste gab bisher IMMER den Menschentext aus, auch bei
        // --format=json/yaml/csv — ein Skript, das die Ausgabe parst, bekam „Die
        // Liste ist leer." statt eines gültigen leeren `[]`. Für die Tabellenform
        // bleibt der Text (er ist dort die bessere Antwort als eine Kopfzeile ohne
        // Zeilen); für die maschinenlesbaren Formate übernimmt format_items() mit
        // einem leeren Array — WP-CLI rendert das als „[]" (json), eine leere Liste
        // (yaml) bzw. nur die Kopfzeile (csv).
        if ( empty( $rows ) && 'table' === $format ) {
            WP_CLI::log( 'Die Liste ist leer.' );
            return;
        }

        \WP_CLI\Utils\format_items( $format, $rows, [ 'eintrag' ] );
    }

    /**
     * Empties the list.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist clear --yes
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function clear( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Die gesamte Liste leeren?', $assoc_args );
        $stored = $this->save( [] );
        if ( ! empty( $stored ) ) {
            // CLI-2: Auch das Leeren kann beim Speichern rückgängig gemacht
            // werden (z. B. wenn ein Schreibpfad die Liste aus dem Altzustand
            // restauriert). Dann darf hier kein Erfolg gemeldet werden.
            WP_CLI::error(
                sprintf(
                    'Die Liste „%s" enthält nach dem Speichern weiterhin %d Eintrag/Einträge — der Schreibvorgang wurde nicht übernommen.',
                    $this->key,
                    count( $stored )
                )
            );
        }
        WP_CLI::success( 'Liste geleert.' );
    }

    /**
     * The current list value.
     *
     * @param bool $force_refresh Read the option again instead of using the
     *                            request-lokalen Settings-Cache.
     * @return array<int, string>
     */
    private function current( bool $force_refresh = false ): array {
        $settings = creationell_captcha_get_settings( $force_refresh );
        $list     = $settings[ $this->key ] ?? [];

        return is_array( $list ) ? array_values( array_map( 'strval', $list ) ) : [];
    }

    /**
     * Writes the list back through the settings sanitiser and returns the list
     * as it is stored afterwards.
     *
     * Der Rückgabewert ist der frisch gelesene Stand, nicht die Eingabe: nur so
     * kann der Aufrufer melden, was wirklich passiert ist (CLI-2). Der Kontext
     * wird ausdrücklich mitgegeben, damit ein späterer Wechsel des Default-Werts
     * von creationell_captcha_sanitize_settings() die CLI nicht still auf die
     * Formular-Semantik (requires-Rückschreibung) umstellt.
     *
     * @param array<int, string> $list The new list.
     * @return array<int, string> Der nach dem Schreiben gespeicherte Stand.
     */
    private function save( array $list ): array {
        $settings               = creationell_captcha_get_settings();
        $settings[ $this->key ] = $list;
        creationell_captcha_store_settings(
            creationell_captcha_sanitize_settings( $settings, \CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC )
        );

        return $this->current( true );
    }

    /**
     * Warns about entries that were already stored before this command ran and
     * are gone afterwards without having been removed on purpose.
     *
     * Das passiert, wenn ein Altbestand die heutige Validierung nicht mehr
     * besteht (etwa ein vor Modul 27 gespeichertes `0.0.0.0/0`): der Sanitizer
     * verwirft ihn beim nächsten Schreibvorgang. Der Schreibvorgang selbst ist
     * erfolgreich — deshalb Warnung, kein Fehler.
     *
     * @param array<int, string> $before    Stand vor dem Schreiben.
     * @param array<int, string> $stored    Stand nach dem Schreiben.
     * @param array<int, string> $intended  Absichtlich entfernte Einträge.
     */
    private function report_collateral_drops( array $before, array $stored, array $intended = [] ): void {
        $dropped = array_values( array_diff( $before, $stored, $intended ) );
        if ( empty( $dropped ) ) {
            return;
        }

        WP_CLI::warning(
            sprintf(
                '%d bereits gespeicherte(r) Eintrag/Einträge wurde(n) beim Speichern von der Sanitisierung verworfen: %s.',
                count( $dropped ),
                implode( ', ', $dropped )
            )
        );
    }

    /**
     * Validates and normalises one entry; returns null when invalid.
     *
     * Öffentlich, weil dies die Validierungs-Nahtstelle der CLI ist und der
     * Ebene-2-Test genau sie prüfen muss (CLI-1). Kein Aufrufer außerhalb
     * dieser Klasse und der Tests benutzt sie.
     *
     * @param string $raw Raw entry value.
     */
    public function normalise( string $raw ): ?string {
        $entry = trim( $raw );
        if ( '' === $entry || strlen( $entry ) > 255 ) {
            return null;
        }

        switch ( $this->validation ) {
            case 'ip':
                // CLI-1: Die CLI hielt bis Modul 27 eine eigene Kopie dieser
                // Prüfung, die `bits >= 0` erlaubte — `0.0.0.0/0` kam damit
                // durch die CLI, wurde vom Sanitizer beim Speichern aber
                // verworfen, während die CLI Erfolg meldete. Eine zweite
                // Validierungsschicht mit eigenen Regeln ist genau der Defekt;
                // deshalb entscheidet hier die Wurzelfunktion aus helpers.php,
                // dieselbe, die auch beim Speichern greift.
                return creationell_captcha_is_valid_ip_or_cidr( $entry ) ? $entry : null;
            case 'action':
                return creationell_captcha_validate_action_pattern( $entry );
            case 'cookie':
                return creationell_captcha_validate_cookie_entry( $entry );
            case 'text':
            default:
                return $entry;
        }
    }

    /**
     * A human-readable reason why normalise() refused this value.
     *
     * Die Begründungen benennen jeweils die Regel, an der die Prüfung
     * scheitert — „ist kein gültiger Eintrag" sagte dem Aufrufer nichts.
     * Öffentlich aus demselben Grund wie normalise().
     *
     * @param string $raw Raw entry value.
     */
    public function reject_reason( string $raw ): string {
        $entry = trim( $raw );
        if ( '' === $entry ) {
            return 'leerer Wert.';
        }
        if ( strlen( $entry ) > 255 ) {
            return sprintf( 'länger als 255 Zeichen (%d).', strlen( $entry ) );
        }

        switch ( $this->validation ) {
            case 'ip':
                $slash = strpos( $entry, '/' );
                if ( false !== $slash ) {
                    $subnet = substr( $entry, 0, $slash );
                    $bits   = substr( $entry, $slash + 1 );
                    if ( ctype_digit( $bits ) && 0 === (int) $bits && false !== @inet_pton( $subnet ) ) {
                        // CLI-1: Der Wert ist syntaktisch korrektes CIDR, aber
                        // ein Catch-all. Er soll nicht kommentarlos „ungültig"
                        // heißen, sondern erklären, warum er abgelehnt wird.
                        //
                        // B-M22: die Begründung ist listenabhängig — "würde die
                        // Liste außer Kraft setzen" stimmt nur für eine ALLOW-
                        // artige Liste (firewall_ip_allow, firewall_trusted_proxies):
                        // dort bewirkt "trifft jede Adresse" einen Totalbypass.
                        // Für firewall_ip_block ist die Wirkung das GEGENTEIL —
                        // "trifft jede Adresse" sperrt jeden Besucher (inkl.
                        // Admin), keine Auflösung der Liste (hardening-migration.php
                        // benennt das an derselben Stelle bewusst NICHT als Fund,
                        // weil "0.0.0.0/0 sperren" ein legitimes Whitelist-only-
                        // Muster ist). Für code_challenge_watchlist bedeutet es
                        // "jeder bekommt die Bild-Eingabe" statt "Liste wirkungslos".
                        return $this->prefix_zero_reject_reason();
                    }
                }
                return 'keine gültige IP-Adresse und kein gültiger CIDR-Bereich (Präfixlänge 1–32 bzw. 1–128).';
            case 'action':
                return 'kein gültiges Aktionsmuster — erlaubt sind A–Z, a–z, 0–9, „_", „-" und „*", optional mit führendem „!" als Ausschluss.';
            case 'cookie':
                return 'kein gültiges „name=wert"-Paar — der Name darf nur A–Z, a–z, 0–9, „_" und „-" enthalten, der Wert höchstens 200 Byte und darf nach der Sanitisierung nicht leer sein.';
            case 'text':
            default:
                // Für 'text' lehnt normalise() nur leere und zu lange Werte ab;
                // beide sind oben abgefangen. Dieser Zweig ist der Fallback für
                // einen künftigen Validierungstyp ohne eigene Begründung.
                return 'wird von der Validierung dieser Liste nicht angenommen.';
        }
    }

    /**
     * Listenabhängige Begründung für die Ablehnung einer Präfixlänge-0-CIDR
     * (`0.0.0.0/0`, `::/0`) — B-M22.
     *
     * `creationell_captcha_is_valid_ip_or_cidr()` (die Wurzelfunktion, die
     * `normalise()` für den Typ 'ip' aufruft) lehnt Präfixlänge 0 für jede
     * 'ip'-Liste einheitlich ab; nur der ERKLÄRENDE TEXT muss zur jeweiligen
     * Liste passen, sonst behauptet die Meldung eine Wirkung, die für diese
     * Liste gar nicht zutrifft.
     */
    private function prefix_zero_reject_reason(): string {
        if ( 'firewall_ip_block' === $this->key ) {
            return 'Präfixlänge 0 trifft jede Adresse — als Blockliste-Eintrag würde das jeden Besucher aussperren (inklusive Ihnen selbst), nicht die Liste außer Kraft setzen. Wer wirklich den gesamten IPv4-Raum sperren will, schreibt ihn als 0.0.0.0/1 und 128.0.0.0/1 aus.';
        }
        if ( 'code_challenge_watchlist' === $this->key ) {
            return 'Präfixlänge 0 trifft jede Adresse — als Watch-Liste-Eintrag bekäme jeder Besucher zusätzlich die Bild-Eingabe vorgelegt, statt dass die Liste als Auswahl wirkt. Wer wirklich alle Besucher meint, schreibt es als 0.0.0.0/1 und 128.0.0.0/1 aus.';
        }

        // firewall_ip_allow, firewall_trusted_proxies: hier stimmt die
        // ursprüngliche Formulierung — ein Catch-all IST hier ein Totalbypass
        // bzw. eine vertrauenswürdig-jeder-Proxy-Zeile.
        return 'Präfixlänge 0 trifft jede Adresse und würde die Liste, in der der Eintrag steht, vollständig außer Kraft setzen. Wer wirklich den gesamten IPv4-Raum meint, schreibt ihn als 0.0.0.0/1 und 128.0.0.0/1 aus.';
    }
}
