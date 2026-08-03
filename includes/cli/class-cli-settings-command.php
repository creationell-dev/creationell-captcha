<?php
/**
 * WP-CLI "settings" subcommands for CreaCaptcha.
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
 * Reads, writes, exports, imports and resets CreaCaptcha settings.
 */
class Settings_Command {

    /**
     * Lists all settings as key/value pairs.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings list
     *
     * @subcommand list
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function list_settings( $args, $assoc_args ): void {
        $format   = $assoc_args['format'] ?? 'table';
        $settings = creationell_captcha_get_settings();

        $rows      = [];
        $sensitive = [];
        foreach ( $settings as $key => $value ) {
            $rows[] = [
                'schluessel' => (string) $key,
                'wert'       => $this->stringify( $value ),
            ];
            $notice = self::sensitive_value_notice( (string) $key, $value );
            if ( null !== $notice ) {
                $sensitive[] = $notice;
            }
        }

        // B-M22: `settings export` warnt seit CLI-6 vor Klartext-Geheimnissen in
        // der Ausgabe (Bypass-Cookies, IP-Erlaubnisliste); `list`/`get` gaben
        // dieselben Werte ohne jede Warnung aus. WP_CLI::warning() schreibt nach
        // STDERR, verändert also nichts an einer geskripteten Auswertung von
        // STDOUT (auch nicht bei --format=json).
        if ( ! empty( $sensitive ) ) {
            WP_CLI::warning( 'Diese Ausgabe enthält: ' . implode( '; ', $sensitive ) . '.' );
        }

        \WP_CLI\Utils\format_items( $format, $rows, [ 'schluessel', 'wert' ] );
    }

    /**
     * Prints one setting value.
     *
     * ## OPTIONS
     *
     * <key>
     * : The setting key.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings get difficulty
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function get( $args, $assoc_args ): void {
        $key      = (string) ( $args[0] ?? '' );
        $settings = creationell_captcha_get_settings();

        if ( ! array_key_exists( $key, $settings ) ) {
            WP_CLI::error( sprintf( 'Unbekannter Schlüssel „%s".', $key ) );
        }

        // B-M22: siehe list_settings() oben — dieselbe Warnung für den Einzelwert.
        $notice = self::sensitive_value_notice( $key, $settings[ $key ] );
        if ( null !== $notice ) {
            WP_CLI::warning( $notice . '.' );
        }

        WP_CLI::line( $this->stringify( $settings[ $key ] ) );
    }

    /**
     * Warnt vor Klartext-Geheimnissen, die eine Ausgabe gleich mitliefert —
     * dieselben zwei Felder, die `export()` schon benennt (B-M22).
     *
     * Öffentlich, weil dies die Entscheidungs-Nahtstelle ist, die
     * `tests/test-cli-output-accuracy.php` direkt prüfen muss (dasselbe Muster wie
     * `List_Command::normalise()`/`reject_reason()`).
     *
     * @param string $key   Settings-Schlüssel.
     * @param mixed  $value Zugehöriger Wert.
     */
    public static function sensitive_value_notice( string $key, $value ): ?string {
        if ( 'bypass_cookies' === $key && ! empty( $value ) ) {
            return sprintf( '%d Bypass-Cookie(s) im Klartext (name=wert — wer sie kennt, umgeht jede Prüfung)', count( (array) $value ) );
        }
        if ( 'firewall_ip_allow' === $key && ! empty( $value ) ) {
            return sprintf( '%d Eintrag/Einträge der IP-Erlaubnisliste', count( (array) $value ) );
        }

        return null;
    }

    /**
     * Sets one setting value.
     *
     * ## OPTIONS
     *
     * <key>
     * : The setting key.
     *
     * <value>
     * : The new value. Checkboxes accept true/false/1/0/yes/no/on/off — jedes
     *   andere Wort ist ein Fehler (Exit 1), kein stilles „false".
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings set difficulty high
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function set( $args, $assoc_args ): void {
        $key   = (string) ( $args[0] ?? '' );
        $value = (string) ( $args[1] ?? '' );

        $fields = creationell_captcha_settings_fields();
        if ( ! isset( $fields[ $key ] ) ) {
            WP_CLI::error( sprintf( 'Unbekannter oder nicht setzbarer Schlüssel „%s".', $key ) );
        }

        $field = $fields[ $key ];
        if ( 'textarea' === ( $field['type'] ?? '' ) ) {
            WP_CLI::error(
                sprintf(
                    'Der Schlüssel „%s" ist eine Liste. Bitte die Befehle blocklist / allowlist / ua-blocklist / paths / trusted-proxies / bypass-ua / bypass-cookies / actions / inject-paths / watchlist verwenden.',
                    $key
                )
            );
        }

        $settings = creationell_captcha_get_settings();

        switch ( $field['type'] ) {
            case 'checkbox':
                // CLI-4: kein stilles FALSE mehr für unbekannte Wörter.
                $parsed = self::parse_bool( $value );
                if ( null === $parsed ) {
                    WP_CLI::error(
                        sprintf(
                            'Der Schlüssel „%s" ist ein Schalter; „%s" ist weder wahr noch falsch. Erlaubt für AN: %s. Erlaubt für AUS: %s.',
                            $key,
                            $value,
                            implode( ', ', self::BOOL_WORDS['true'] ),
                            implode( ', ', self::BOOL_WORDS['false'] )
                        )
                    );
                }
                $settings[ $key ] = $parsed;
                break;
            case 'number':
                if ( ! is_numeric( $value ) ) {
                    WP_CLI::error( sprintf( 'Der Schlüssel „%s" erwartet einen numerischen Wert.', $key ) );
                }
                $settings[ $key ] = (int) $value;
                break;
            case 'select':
                if ( ! array_key_exists( $value, $field['options'] ?? [] ) ) {
                    WP_CLI::error(
                        'Ungültiger Wert. Erlaubt: ' . implode( ', ', array_keys( $field['options'] ?? [] ) ) . '.'
                    );
                }
                $settings[ $key ] = $value;
                break;
            case 'text':
            case 'color':
            case 'textblock':
                $settings[ $key ] = $value;
                break;
            default:
                WP_CLI::error( 'Dieser Feldtyp wird vom set-Befehl nicht unterstützt.' );
        }

        $clean = creationell_captcha_sanitize_settings( $settings );
        $input_was_non_empty = '' !== trim( $value );
        $stored_is_empty     = ( '' === (string) ( $clean[ $key ] ?? '' ) );
        if ( in_array( $field['type'], [ 'color', 'textblock' ], true ) && $input_was_non_empty && $stored_is_empty ) {
            WP_CLI::warning(
                sprintf(
                    'Wert für „%s" wurde von der Sanitisierung verworfen (ungültiges JSON bei widget_strings_override oder ungültiger Hex-Wert bei widget_primary_color).',
                    $key
                )
            );
        }
        creationell_captcha_store_settings( $clean );

        WP_CLI::success( sprintf( '%s = %s', $key, $this->stringify( $clean[ $key ] ) ) );
    }

    /**
     * Exports all settings as JSON.
     *
     * Die Ausgabe enthält Klartext-Geheimnisse: `bypass_cookies` sind
     * `name=wert`-Paare, mit denen jeder Client den kompletten Schutz umgeht,
     * und `firewall_ip_allow` beschreibt, wer ihn ohne Prüfung passiert. Nur
     * die HMAC-Signaturschlüssel sind bewusst ausgenommen. Die Datei ist damit
     * so schützenswert wie ein Passwort — `--file` legt sie deshalb mit den
     * Rechten 0600 an und weist auf einen Pfad im Web-Root hin (CLI-6).
     *
     * ## OPTIONS
     *
     * [--file=<path>]
     * : Write to this file instead of STDOUT. Die Datei wird mit den Rechten
     *   0600 (nur der ausführende Benutzer) angelegt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings export --file=backup.json
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function export( $args, $assoc_args ): void {
        $payload = creationell_captcha_export_settings();
        $json    = wp_json_encode(
            $payload,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        if ( false === $json ) {
            WP_CLI::error( 'Einstellungen konnten nicht als JSON kodiert werden.' );
        }

        // CLI-6: Der Export war als „nur die HMAC-Secrets fehlen" dokumentiert —
        // was stimmt, aber verschweigt, dass die Bypass-Cookies selbst
        // Zugangsgeheimnisse sind. Die Warnung nennt konkret, was in der Datei
        // steht, und erscheint nur dann, wenn wirklich etwas darin steht.
        //
        // B-M22: dieselbe Ermittlung wie in list_settings()/get() — ein Ort für
        // die Frage „ist dieser Wert ein Klartext-Geheimnis".
        $settings  = is_array( $payload['settings'] ?? null ) ? $payload['settings'] : [];
        $sensitive = [];
        foreach ( $settings as $key => $value ) {
            $notice = self::sensitive_value_notice( (string) $key, $value );
            if ( null !== $notice ) {
                $sensitive[] = $notice;
            }
        }
        if ( ! empty( $sensitive ) ) {
            WP_CLI::warning( 'Der Export enthält: ' . implode( '; ', $sensitive ) . '. Die HMAC-Signaturschlüssel sind ausgenommen.' );
        }

        if ( isset( $assoc_args['file'] ) ) {
            $path = (string) $assoc_args['file'];
            $this->warn_if_inside_webroot( $path );

            // CLI-6: `file_put_contents()` legte die Datei mit den Rechten der
            // Umask an — typischerweise 0644, also für jeden Systembenutzer
            // lesbar. Deshalb erst anlegen ('c' erzeugt, ohne zu kürzen), dann
            // chmod, dann erst den Inhalt schreiben: das Zeitfenster zwischen
            // Anlegen und chmod enthält noch keine Daten. Eine bereits
            // bestehende Datei wird ebenfalls auf 0600 gesetzt, bevor der neue
            // Inhalt hineingeht.
            $handle = @fopen( $path, 'c' );
            if ( false === $handle ) {
                WP_CLI::error( sprintf( 'Datei „%s" konnte nicht geöffnet werden.', $path ) );
            }

            // Nur bei einer gewöhnlichen Datei sind Rechte und Kürzen
            // überhaupt sinnvoll. `--file=/dev/stdout` oder eine FIFO haben
            // beides nicht — dort würde ein erzwungenes chmod den bisher
            // funktionierenden Aufruf abbrechen.
            $stat        = fstat( $handle );
            $is_regular  = is_array( $stat ) && 0x8000 === ( ( (int) $stat['mode'] ) & 0xF000 );
            $permissions = 'unverändert (keine gewöhnliche Datei)';

            if ( $is_regular ) {
                if ( ! @chmod( $path, 0600 ) ) {
                    fclose( $handle );
                    WP_CLI::error(
                        sprintf(
                            'Die Rechte von „%s" konnten nicht auf 0600 gesetzt werden — der Export wurde NICHT geschrieben. Ohne diese Einschränkung läge eine Datei mit Bypass-Cookies im Klartext für jeden Systembenutzer lesbar da.',
                            $path
                        )
                    );
                }
                $permissions = '0600';
                ftruncate( $handle, 0 );
            }

            if ( false === fwrite( $handle, $json . "\n" ) ) {
                fclose( $handle );
                WP_CLI::error( sprintf( 'Datei „%s" konnte nicht geschrieben werden.', $path ) );
            }
            fclose( $handle );

            WP_CLI::success( sprintf( 'Einstellungen nach „%s" exportiert (Rechte: %s).', $path, $permissions ) );
            return;
        }

        WP_CLI::line( (string) $json );
    }

    /**
     * Warns when the export target lies inside the WordPress installation
     * directory and would therefore likely be reachable over HTTP.
     *
     * Bewusst eine Warnung, kein Fehler: Ob ein Pfad wirklich ausgeliefert
     * wird, hängt von der Webserver-Konfiguration ab, die hier niemand kennt.
     * Die Prüfung behauptet nur, was sie sieht — dass der Pfad unterhalb von
     * ABSPATH liegt.
     *
     * @param string $path Target path as given on the command line.
     */
    private function warn_if_inside_webroot( string $path ): void {
        if ( ! defined( 'ABSPATH' ) ) {
            return;
        }

        $dir = realpath( '' === dirname( $path ) ? '.' : dirname( $path ) );
        $abs = realpath( ABSPATH );
        if ( false === $dir || false === $abs ) {
            return;
        }

        $dir = rtrim( $dir, '/' ) . '/';
        $abs = rtrim( $abs, '/' ) . '/';
        if ( ! str_starts_with( $dir, $abs ) ) {
            return;
        }

        WP_CLI::warning(
            sprintf(
                'Der Zielpfad liegt unterhalb der WordPress-Installation (%s) und ist damit möglicherweise über HTTP abrufbar. Ob er es wirklich ist, entscheidet die Webserver-Konfiguration — sicherer ist ein Pfad außerhalb des Web-Roots.',
                $abs
            )
        );
    }

    /**
     * Imports settings from a JSON file.
     *
     * ## OPTIONS
     *
     * <file>
     * : Path to a settings-export JSON file.
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings import backup.json
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function import( $args, $assoc_args ): void {
        $path = (string) ( $args[0] ?? '' );
        if ( '' === $path || ! is_readable( $path ) ) {
            WP_CLI::error( sprintf( 'Datei „%s" nicht lesbar.', $path ) );
        }

        $raw = file_get_contents( $path );
        if ( false === $raw ) {
            WP_CLI::error( sprintf( 'Datei „%s" konnte nicht gelesen werden.', $path ) );
        }

        $payload = json_decode( $raw, true );
        if ( ! is_array( $payload ) ) {
            WP_CLI::error( 'Die Datei ist kein gültiges JSON.' );
        }

        WP_CLI::confirm( 'Die aktuelle Konfiguration wird ersetzt. Fortfahren?', $assoc_args );

        $result = creationell_captcha_import_settings( $payload );
        if ( is_wp_error( $result ) ) {
            WP_CLI::error( $result->get_error_message() );
        }

        if ( ! empty( $result['version_notice'] ) ) {
            WP_CLI::warning( $result['version_notice'] );
        }
        // W2-10: source_notice (AF-6-Transparenz — "diese Datei stammt von
        // fremde-site.example") erreichte bisher den CLI-Importweg nicht, obwohl
        // creationell_captcha_import_settings() sie seit dieser Runde immer
        // liefert (settings-manager.php:130-146) und der Befehl mit
        // WP_CLI::confirm() bereits eine Stelle hat, in die die Meldung passt.
        if ( ! empty( $result['source_notice'] ) ) {
            WP_CLI::warning( $result['source_notice'] );
        }
        WP_CLI::success( 'Einstellungen importiert.' );
    }

    /**
     * Resets every setting to its default — including emptying all lists.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings reset --yes
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function reset( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Alle Einstellungen inklusive der Listen auf Werkseinstellungen zurücksetzen?', $assoc_args );
        creationell_captcha_reset_settings();

        // Nachlese N2: der Kommentar behauptete "schreibt die Option direkt, ohne
        // creationell_captcha_sanitize_settings()" — seit Welle 1 (E3a, Commit
        // 7491fff) stimmt das nicht mehr: creationell_captcha_reset_settings()
        // ruft den Sanitizer jetzt explizit mit CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC
        // auf, bevor sie schreibt (settings-manager.php:173-184). Bei `reset`
        // bleibt das folgenlos — geschrieben werden ausschließlich die
        // hartkodierten Defaults, die schon sauber sind. Was weiterhin gilt:
        // die Ereignis-Tabelle entsteht hier NICHT von selbst (`ensure_table()`
        // hängt seit derselben Welle an den update_option_.../add_option_-Hooks
        // von settings.php, nicht mehr am Sanitizer — reset() setzt
        // analytics_event_log ohnehin auf den Default `aus`, also bräuchte sie
        // hier niemand); wer das Log danach wieder einschaltet, bekommt sie über
        // `enable event-log` bzw. `repair`. Statt das stillschweigend
        // vorauszusetzen, steht es in der Meldung.
        $this->report_reset_state( 'Auf Werkseinstellungen zurückgesetzt; alle Listen sind leer.' );
    }

    /**
     * Resets configuration values to default but keeps the lists.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha settings load-defaults --yes
     *
     * @subcommand load-defaults
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function load_defaults( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Alle Konfigurationswerte auf Standard zurücksetzen? Die Listen bleiben erhalten.', $assoc_args );

        $before = creationell_captcha_get_settings();
        creationell_captcha_load_default_settings();
        $after = creationell_captcha_get_settings( true );

        // Nachlese N2: die bisherige Meldung behauptete, die übernommenen
        // Listenwerte würden "NICHT erneut validiert" — das stimmte seit Welle 1
        // (E3a, Commit 7491fff) nicht mehr: creationell_captcha_load_default_settings()
        // (settings-manager.php:197-224) übergibt den kompletten Wertesatz
        // inklusive der übernommenen Listen jetzt explizit an
        // creationell_captcha_sanitize_settings(), bevor sie schreibt. Statt die
        // überholte Behauptung stehen zu lassen (Fehlerklasse 3 — der Code
        // validiert längst, die Meldung sagte das Gegenteil), wird jetzt am
        // tatsächlich gespeicherten Stand gemessen, was passiert ist — dasselbe
        // "Absicht gegen Ergebnis"-Muster wie List_Command::add()/remove() (CLI-1/CLI-2).
        $dropped = self::count_dropped_list_entries( $before, $after, creationell_captcha_list_setting_keys() );
        if ( $dropped > 0 ) {
            WP_CLI::warning(
                sprintf(
                    '%d Listeneintrag/-einträge wurden beim Übernehmen von der Sanitisierung verworfen (entsprechen nicht mehr der aktuellen Feldspezifikation, z. B. eine vor einer früheren Version gespeicherte Präfixlänge-0-Adresse).',
                    $dropped
                )
            );
        }

        $this->report_reset_state( 'Standardwerte geladen; die Listen blieben erhalten.' );
    }

    /**
     * Zählt, wie viele Listeneinträge zwischen zwei Settings-Ständen verschwunden
     * sind — reine Zähllogik, öffentlich für den direkten Ebene-2-Test (dieselbe
     * Begründung wie bei `sensitive_value_notice()` oben). Zählt nur VERLUSTE
     * (ein Feld mit mehr Einträgen danach als vorher trägt 0 bei, nicht negativ).
     *
     * @param array<string, mixed> $before   Settings vor dem Schreibvorgang.
     * @param array<string, mixed> $after    Settings nach dem Schreibvorgang.
     * @param array<int, string>   $list_keys Zu zählende Listen-Schlüssel.
     */
    public static function count_dropped_list_entries( array $before, array $after, array $list_keys ): int {
        $dropped = 0;
        foreach ( $list_keys as $key ) {
            $before_count = count( (array) ( $before[ $key ] ?? [] ) );
            $after_count  = count( (array) ( $after[ $key ] ?? [] ) );
            $dropped     += max( 0, $before_count - $after_count );
        }

        return $dropped;
    }

    /**
     * Prints the success line of `reset`/`load-defaults` together with the one
     * consequence that is easy to overlook: the event log is back to its
     * default (off).
     *
     * @param string $headline Success message of the calling command.
     */
    private function report_reset_state( string $headline ): void {
        $settings = creationell_captcha_get_settings( true );

        if ( empty( $settings['analytics_event_log'] ) ) {
            $headline .= ' Der Event-Log steht wieder auf dem Standard (aus); die vorhandene Ereignistabelle und ihre Zeilen bleiben unangetastet.';
        }

        WP_CLI::success( $headline );
    }

    /**
     * Converts a setting value to a printable string.
     *
     * @param mixed $value Raw setting value.
     */
    private function stringify( $value ): string {
        if ( is_bool( $value ) ) {
            return $value ? 'true' : 'false';
        }
        if ( is_array( $value ) ) {
            return implode( ', ', array_map( 'strval', $value ) );
        }

        return (string) $value;
    }

    /**
     * The words `parse_bool()` accepts, per resulting value.
     *
     * @var array<string, array<int, string>>
     */
    public const BOOL_WORDS = [
        'true'  => [ '1', 'true', 'yes', 'on' ],
        'false' => [ '0', 'false', 'no', 'off' ],
    ];

    /**
     * Parses a boolean-ish CLI string; NULL for anything that is neither.
     *
     * CLI-4: Die Whitelist war einseitig — alles außer `1/true/yes/on` wurde
     * kommentarlos zu FALSE. `settings set firewall_enabled y` schaltete damit
     * die Firewall AB, obwohl der Aufrufer sie einschalten wollte. Ein Wort,
     * das in keiner der beiden Listen steht, ist keine Angabe von `false`,
     * sondern ein Tippfehler — der Aufrufer bekommt jetzt NULL und darüber
     * einen Fehler statt eines stillen Gegenteils.
     *
     * @param string $value Raw value.
     * @return bool|null TRUE/FALSE bei bekanntem Wort, sonst NULL.
     */
    public static function parse_bool( string $value ): ?bool {
        $normalised = strtolower( trim( $value ) );

        if ( in_array( $normalised, self::BOOL_WORDS['true'], true ) ) {
            return true;
        }
        if ( in_array( $normalised, self::BOOL_WORDS['false'], true ) ) {
            return false;
        }

        return null;
    }
}
