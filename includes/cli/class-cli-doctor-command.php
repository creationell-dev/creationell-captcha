<?php
/**
 * WP-CLI: runs a diagnostic checklist over the CreaCaptcha installation.
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
 * `wp creacaptcha doctor`
 */
class Doctor_Command {

    /**
     * Runs the diagnostic checklist and prints a status table.
     *
     * Exit code 1 if at least one check is `error`, 0 otherwise.
     *
     * Grenze des Werkzeugs (CLI-10): `doctor` liest ausschließlich — es prüft
     * Vorhandensein und Erreichbarkeit (Datei, Option, Tabelle, Cron, Extension)
     * sowie einige Konsistenzen zwischen Schaltern. Seit der Nachlese vergleicht
     * Check 9 den gespeicherten Wertesatz zusätzlich gegen den Sanitizer (rein
     * lesend, siehe dort) und erkennt damit einen an den Plugin-Schreibwegen
     * vorbei gesetzten Wert, der von der Feldspezifikation abweicht
     * (`algorithm=boguswert` per `wp option patch`). Nicht geprüft bleibt, ob
     * ein Wert innerhalb seiner Spezifikation auch inhaltlich sinnvoll ist
     * (ein syntaktisch gültiges, aber unerreichbares Cloudflare-IP-Ziel o. Ä.).
     * „status: ok" heißt deshalb „dieser Check hat nichts gefunden", nicht
     * „die Installation ist korrekt konfiguriert".
     *
     * Third-party modules can extend the list via the
     * `creationell_captcha_doctor_checks` filter. Filter receives the array
     * of checks (each `[check => string, status => 'ok'|'warn'|'error',
     * meldung => string]`) and must return the same shape.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha doctor
     *
     * @when after_wp_load
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function __invoke( array $args, array $assoc_args ): void {
        $format = $assoc_args['format'] ?? 'table';

        if ( ! function_exists( 'is_plugin_active' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $settings = creationell_captcha_get_settings();

        $checks = [];

        // 1. Vendored library — Strauss writes to lib/<package-path>/src/, the
        //    canonical signal that the build has been run is lib/autoload.php.
        //
        //    B-M22: this check (and Check 7 below) can structurally never report its
        //    `error` branch. `creationell-captcha.php:44-84` performs the identical
        //    file_exists()/PHP-version check at plugin-load time and `return`s before
        //    registering `includes/cli/`, so the `doctor` command does not exist at all
        //    when either condition is false — there is no code path that reaches this
        //    line with a missing lib/ or an unsupported PHP version. Kept anyway (not
        //    dead code to delete) as an explicit environment confirmation in the output
        //    table, e.g. for `--format=json` consumers that assert on this row's
        //    presence; `error` remains correct in spirit, it is just unreachable today.
        $lib_autoload = CREATIONELL_CAPTCHA_PLUGIN_PATH . 'lib/autoload.php';
        $checks[] = file_exists( $lib_autoload )
            ? [ 'check' => 'Vendored Library', 'status' => 'ok', 'meldung' => dirname( $lib_autoload ) ]
            : [ 'check' => 'Vendored Library', 'status' => 'error', 'meldung' => sprintf( 'Datei fehlt: %s — „composer install" ausführen.', $lib_autoload ) ];

        // 2. HMAC secrets.
        //
        // B-M22: reads BOTH resolution sources of creationell_captcha_get_hmac_secret()/
        // _get_hmac_key_secret() (helpers.php:328-353) — the wp-config constants
        // CREATIONELL_CAPTCHA_HMAC_SECRET/_KEY_SECRET take precedence, the
        // `creationell_captcha_secrets` option is the fallback — instead of only the
        // option. An installation that sets the constants and clears the option used to
        // get `error` + Exit 1 and the advice to run `repair`, which writes an option
        // no code path ever reads once the constants are set.
        //
        // Deliberately NOT calling the getters themselves: creationell_captcha_get_secret()
        // self-heals a missing option by generating and PERSISTING new secrets — a write
        // this read-only diagnostic must never trigger as a side effect of merely checking
        // presence (the class docblock's "doctor liest ausschließlich" contract).
        $secrets_option = get_option( 'creationell_captcha_secrets', [] );
        $checks[]       = self::hmac_secrets_check(
            self::secret_resolvable( 'CREATIONELL_CAPTCHA_HMAC_SECRET', $secrets_option, 'signature' ),
            self::secret_resolvable( 'CREATIONELL_CAPTCHA_HMAC_KEY_SECRET', $secrets_option, 'key_signature' )
        );

        // 3. Event-log table.
        if ( ! empty( $settings['analytics_event_log'] ) ) {
            $analytics    = creationell_captcha_analytics();
            $table_exists = $analytics->table_exists();
            $checks[]     = $table_exists
                ? [ 'check' => 'Event-Log-Tabelle', 'status' => 'ok', 'meldung' => 'vorhanden' ]
                : [ 'check' => 'Event-Log-Tabelle', 'status' => 'error', 'meldung' => 'Tabelle fehlt obwohl Event-Log aktiv — `wp creacaptcha repair` ausführen.' ];
        } else {
            $checks[] = [ 'check' => 'Event-Log-Tabelle', 'status' => 'ok', 'meldung' => 'übersprungen (Event-Log aus)' ];
        }

        // 4. Cloudflare refresh cron.
        $checks[] = self::cloudflare_cron_check(
            $settings,
            wp_next_scheduled( 'creationell_captcha_refresh_cloudflare_ips' )
        );

        // 5. Kill switch.
        $checks[] = creationell_captcha_is_disabled()
            ? [ 'check' => 'Kill-Switch', 'status' => 'warn', 'meldung' => 'CREATIONELL_CAPTCHA_DISABLE ist truthy — Plugin global deaktiviert.' ]
            : [ 'check' => 'Kill-Switch', 'status' => 'ok', 'meldung' => 'inaktiv' ];

        // 6. Conflicting captcha plugins.
        $conflicts = [
            'altcha/altcha.php'                                               => 'ALTCHA (offizielles Plugin)',
            'recaptcha/recaptcha.php'                                         => 'reCAPTCHA',
            'hcaptcha-for-forms-and-more/hcaptcha.php'                        => 'hCaptcha for Forms and More',
            'simple-cloudflare-turnstile/simple-cloudflare-turnstile.php'     => 'Simple Cloudflare Turnstile',
        ];
        $active_conflicts = [];
        foreach ( $conflicts as $slug => $label ) {
            if ( is_plugin_active( $slug ) ) {
                $active_conflicts[] = $label;
            }
        }
        $checks[] = empty( $active_conflicts )
            ? [ 'check' => 'Captcha-Plugin-Konflikte', 'status' => 'ok', 'meldung' => 'keine bekannten Captcha-Plugins aktiv' ]
            : [ 'check' => 'Captcha-Plugin-Konflikte', 'status' => 'warn', 'meldung' => 'aktiv: ' . implode( ', ', $active_conflicts ) ];

        // 7. PHP version — structurally can never report `error`, see the comment on
        //    Check 1 above (creationell-captcha.php gates plugin load on this same test).
        $checks[] = PHP_VERSION_ID >= 80300
            ? [ 'check' => 'PHP-Version', 'status' => 'ok', 'meldung' => PHP_VERSION ]
            : [ 'check' => 'PHP-Version', 'status' => 'error', 'meldung' => sprintf( 'PHP %s — erfordert ≥ 8.3', PHP_VERSION ) ];

        // 7b. Sodium-Extension (für Argon2id-Algorithmus erforderlich).
        $checks[] = self::sodium_check( $settings, creationell_captcha_sodium_available() );

        // 8. Cloudflare cache age.
        if ( ! empty( $settings['firewall_trust_cloudflare'] ) ) {
            $cached     = get_option( 'creationell_captcha_cloudflare_ips', [] );
            $fetched_at = is_array( $cached ) ? (int) ( $cached['fetched_at'] ?? 0 ) : 0;
            if ( $fetched_at <= 0 ) {
                $checks[] = [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'warn', 'meldung' => 'kein Cache vorhanden — `wp creacaptcha cloudflare refresh` ausführen.' ];
            } else {
                $age      = time() - $fetched_at;
                $checks[] = $age > DAY_IN_SECONDS
                    ? [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'warn', 'meldung' => sprintf( 'älter als 24 h (Alter: %s)', human_time_diff( $fetched_at, time() ) ) ]
                    : [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'ok', 'meldung' => sprintf( 'frisch (Alter: %s)', human_time_diff( $fetched_at, time() ) ) ];
            }
        } else {
            $checks[] = [ 'check' => 'Cloudflare-Cache-Alter', 'status' => 'ok', 'meldung' => 'übersprungen (firewall_trust_cloudflare aus)' ];
        }

        // 9. Settings defaults completeness + CLI-10: value-level spec conformance.
        //
        // Nachlese N2: der bisherige Kommentar begründete den Verzicht auf den
        // Sanitizer-Vergleich damit, dass creationell_captcha_sanitize_settings() bei
        // aktivem Event-Log die Tabelle anlegt — dieser Seiteneffekt wurde in Welle 1
        // aus dem Sanitizer selbst entfernt (settings.php: ensure_table() haengt jetzt
        // an den Hooks update_option_.../add_option_creationell_captcha_settings, nicht
        // mehr am Sanitizer-Aufruf). Der Sanitizer ist damit — abgesehen von harmlosen
        // add_settings_error()-Aufrufen, unter WP-CLI leer verpuffend — seiteneffektfrei
        // und fuer einen reinen Vergleich nutzbar. Check 9 kann die CLI-10-Grenze damit
        // schliessen: er ruft den Sanitizer im PROGRAMMATIC-Kontext (keine
        // requires-Rueckschreibung — beim Vergleich von $stored gegen sich selbst waere
        // sie ohnehin ein No-op, siehe settings.php:1295-1327) NUR zum Vergleichen auf,
        // OHNE das Ergebnis zu schreiben.
        $defaults  = creationell_captcha_get_default_settings();
        $stored    = get_option( 'creationell_captcha_settings', [] );
        if ( ! is_array( $stored ) ) {
            $stored = [];
        }
        $sanitized = self::sanitized_snapshot( $stored );
        $checks[]  = self::settings_defaults_check( $defaults, $stored, $sanitized );

        // 10. PHP-GD-Extension (für Code-Challenge erforderlich).
        $checks[] = self::gd_check( $settings, extension_loaded( 'gd' ) );

        // 10b. Code-Challenge-Schriftart — ZP-2: is_file() sieht eine
        //      beschädigte oder ausgetauschte assets/fonts/captcha.ttf nicht;
        //      imagettftext() liefert dann für jedes Zeichen `false`, zeichnet
        //      nichts, und der Besucher bekommt ein leeres weißes PNG statt
        //      eines Codes — fail-closed, aber ohne Log und ohne Hinweis, bis
        //      dieser Check hier existierte. Nur relevant, wenn Code-Challenge
        //      an ist und GD überhaupt lädt (sonst bereits durch Check 10
        //      gemeldet).
        if ( empty( $settings['code_challenge_enabled'] ) ) {
            $checks[] = [ 'check' => 'Code-Challenge-Schriftart', 'status' => 'ok', 'meldung' => 'übersprungen (Code-Challenge aus)' ];
        } elseif ( ! extension_loaded( 'gd' ) ) {
            $checks[] = [ 'check' => 'Code-Challenge-Schriftart', 'status' => 'ok', 'meldung' => 'übersprungen (PHP-GD fehlt — siehe vorheriger Check)' ];
        } else {
            $checks[] = creationell_captcha_code_challenge_font_usable()
                ? [ 'check' => 'Code-Challenge-Schriftart', 'status' => 'ok', 'meldung' => 'assets/fonts/captcha.ttf rendert erfolgreich' ]
                : [
                    'check'   => 'Code-Challenge-Schriftart',
                    'status'  => 'warn',
                    'meldung' => 'assets/fonts/captcha.ttf ist vorhanden, aber unbrauchbar (imagettftext() schlägt fehl — Datei beschädigt oder ersetzt). Fällt automatisch auf die eingebaute Bitmap-Schrift zurück (Besucher sehen weiterhin einen lesbaren Code); Datei prüfen bzw. aus dem Plugin-Paket neu ausliefern.',
                ];
        }

        // 11. Login-form coverage — protect_login covers /wp-login.php and
        //     wp_login_form()-based theme/widget logins (IN-6), but NOT the
        //     WooCommerce My-Account login form, which posts different field
        //     names and has its own dedicated toggle (IN-7).
        $checks[] = self::login_coverage_row( $settings );

        // 12. WooCommerce-Checkout-Typ — IN-2: der Checkout-Schutz (Widget +
        //     Verify) hängt ausschliesslich am klassischen
        //     process_checkout()-Pfad; die Store-API-Route des Block-
        //     Checkouts ruft ihn nie auf. Bei aktivem protect_wc_checkout und
        //     einer als Block-Checkout erkannten Checkout-Seite waere die
        //     bisherige stille "aktiviert" = "geschuetzt"-Annahme irrefuehrend.
        //     Nutzt creationell_captcha_wc_checkout_active() (statt den
        //     Toggle isoliert zu lesen) — Review-Fund (Fix-Runde 1): sonst
        //     warnt der Check auch dann, wenn der Master protect_woocommerce
        //     aus ist (oder der Kill-Switch greift) und protect_wc_checkout
        //     nur eingefroren true dasteht (AF-1), obwohl der Checkout-Schutz
        //     dann ohnehin komplett inaktiv ist — irrefuehrend in beide
        //     Richtungen.
        if ( creationell_captcha_wc_checkout_active() ) {
            if ( creationell_captcha_wc_uses_block_checkout() ) {
                $checks[] = [
                    'check'   => 'WooCommerce-Checkout-Typ',
                    'status'  => 'warn',
                    'meldung' => 'Aktive Checkout-Seite nutzt den Block-Checkout (wp:woocommerce/checkout) — "Checkout schützen" hat dort KEINE Wirkung (kein Widget, keine Verifikation; die Store-API-Route ruft process_checkout() nie auf). Nur der klassische [woocommerce_checkout]-Shortcode-Checkout ist geschützt.',
                ];
            } else {
                $checks[] = [ 'check' => 'WooCommerce-Checkout-Typ', 'status' => 'ok', 'meldung' => 'klassischer Checkout ([woocommerce_checkout]) — geschützt' ];
            }
        } else {
            $checks[] = [ 'check' => 'WooCommerce-Checkout-Typ', 'status' => 'ok', 'meldung' => 'übersprungen (Checkout-Schutz inaktiv: WooCommerce inaktiv, Kill-Switch, protect_woocommerce aus oder protect_wc_checkout aus)' ];
        }

        // 13. WooCommerce-Lost-Password Render-/Verify-Split — IN-5:
        //     protect_wc_lost_password steuert NUR das Widget-Rendering auf
        //     Woos eigenem Template; die serverseitige Pruefung laeuft
        //     ausschliesslich ueber das Kernmodul protect_password_reset
        //     (lostpassword_post). Beide Schalter sind unabhaengig
        //     voneinander konfigurierbar. Nutzt die echten _active()/
        //     _enabled()-Helper (statt die Toggles isoliert zu lesen) —
        //     analog zum Checkout-Typ-Check oben (Review-Fund, Fix-Runde 1):
        //     protect_password_reset wirkt IMMER (Kernmodul, unabhaengig von
        //     protect_woocommerce), waehrend das Woo-Render nur bei aktivem
        //     Master + Kill-Switch-aus greift — ein reiner
        //     protect_woocommerce-Gate auf den ganzen Check haette den Split
        //     genau dann uebersehen, wenn der Master aus, aber
        //     protect_password_reset trotzdem an ist.
        if ( class_exists( 'WooCommerce' ) ) {
            $render_on = creationell_captcha_wc_lost_password_active();
            $verify_on = creationell_captcha_password_reset_enabled();
            if ( $render_on && ! $verify_on ) {
                $checks[] = [
                    'check'   => 'WooCommerce-Lost-Password-Kopplung',
                    'status'  => 'warn',
                    'meldung' => 'Widget wird auf der Woo-Lost-Password-Seite angezeigt (protect_wc_lost_password an), aber die Verifikation ist aus (protect_password_reset aus) — jede Reset-Anfrage geht ohne Prüfung durch (fail-open). "Passwort-Reset schützen" (Kernformulare) ebenfalls aktivieren.',
                ];
            } elseif ( ! $render_on && $verify_on ) {
                // B-M22: die Ursache fest auf "(protect_wc_lost_password aus)" zu
                // benennen war falsch, sobald $render_on aus einem anderen Grund
                // false ist — creationell_captcha_wc_lost_password_active() ist auch
                // dann false, wenn der Kill-Switch greift oder protect_woocommerce
                // aus ist, unabhängig vom Stand von protect_wc_lost_password selbst
                // (dasselbe Muster wie Check 12 oben, das alle vier Ursachen nennt).
                $checks[] = [
                    'check'   => 'WooCommerce-Lost-Password-Kopplung',
                    'status'  => 'warn',
                    'meldung' => 'Verifikation ist aktiv (protect_password_reset an), aber kein Widget auf der Woo-Lost-Password-Seite — jede Reset-Anfrage über diese Seite scheitert. Ursache: Kill-Switch, protect_woocommerce aus oder protect_wc_lost_password aus. "Lost-Password schützen" (WooCommerce) ebenfalls aktivieren.',
                ];
            } else {
                $checks[] = [ 'check' => 'WooCommerce-Lost-Password-Kopplung', 'status' => 'ok', 'meldung' => sprintf( 'konsistent (Widget: %s, Verifikation: %s)', $render_on ? 'an' : 'aus', $verify_on ? 'an' : 'aus' ) ];
            }
        } else {
            $checks[] = [ 'check' => 'WooCommerce-Lost-Password-Kopplung', 'status' => 'ok', 'meldung' => 'übersprungen (WooCommerce inaktiv)' ];
        }

        // W1-9: both the exclusion check (14) and the inject-coverage check
        // (15) below used to read `interceptor_paths`/`interceptor_actions`
        // straight from settings. The interceptor itself never decides on
        // that raw array — Interceptor::is_guarded()/action_patterns() always
        // run it through `apply_filters('creationell_captcha_interceptor_paths'
        // /_actions', …)` first, which is also the documented way for a site
        // to add a guard via creationell_captcha_protect_path() without ever
        // touching the settings option. Reading raw settings here made both
        // checks blind to filter-only entries and blind to a filter that
        // REMOVES a settings entry. `interceptor_inject_paths` has no such
        // filter at its one runtime read site (interceptor-inject.php) and
        // stays a raw settings read.
        $guarded       = self::filtered_interceptor_lists( $settings );
        $guard_paths   = $guarded['paths'];
        $guard_actions = $guarded['actions'];

        // 14. Interceptor exclusion patterns — BK-15: `!`-entries are hard
        //     excludes that short-circuit the WHOLE list regardless of order
        //     (documented allow-list semantics, see the match_path() docblock).
        //     An over-broad entry such as `!*` therefore silently switches the
        //     entire protected-paths/-actions list off. The semantics stay as
        //     they are; the footgun is made visible here instead.
        $overbroad = [];
        foreach ( [ 'Geschützte Pfade' => $guard_paths, 'Geschützte Aktionen' => $guard_actions ] as $label => $filtered_list ) {
            foreach ( self::neutralising_excludes( $filtered_list ) as $pattern ) {
                $overbroad[] = sprintf( '%s: „%s"', $label, $pattern );
            }
        }
        if ( empty( $overbroad ) ) {
            $checks[] = [ 'check' => 'Interceptor-Ausschlussmuster', 'status' => 'ok', 'meldung' => 'kein Ausschlussmuster hebt die eigene Liste auf' ];
        } else {
            $checks[] = [
                'check'   => 'Interceptor-Ausschlussmuster',
                'status'  => 'warn',
                'meldung' => 'Ein Ausschlussmuster („!"-Zeile) trifft auf jedes positive Muster derselben Liste zu und schaltet sie damit komplett ab — '
                    . implode( ', ', $overbroad )
                    . '. Ein „!"-Treffer wirkt reihenfolgeunabhängig auf die gesamte Liste (Allow-Listen-Semantik). Zeile entfernen oder enger fassen.',
            ];
        }

        // 15. Inject-Pfade ohne serverseitige Prüfung — CM-11(a): das Widget
        //     wird auf jedem interceptor_inject_paths-Treffer gerendert, aber
        //     geprüft wird nur, was interceptor_paths/-actions abdeckt. Ein
        //     Inject-Pfad ohne Gegenstück sieht geschützt aus und ist es nicht.
        //     Zusätzlich BK-6: der Guard hängt am URL-Pfad bzw. am
        //     action-Namen — ein Handler an `init`/`admin_post`, der beides
        //     ignoriert, läuft auch bei einem POST auf eine ungelistete URL.
        $inject_paths = array_values( array_filter(
            array_map( 'strval', (array) ( $settings['interceptor_inject_paths'] ?? [] ) ),
            static function ( string $pattern ): bool {
                $pattern = trim( $pattern );
                return '' !== $pattern && ! str_starts_with( $pattern, '!' );
            }
        ) );

        if ( empty( $inject_paths ) ) {
            $checks[] = [ 'check' => 'Inject-Pfade-Abdeckung', 'status' => 'ok', 'meldung' => 'übersprungen (keine Inject-Pfade konfiguriert)' ];
        } else {
            $uncovered = [];
            foreach ( $inject_paths as $pattern ) {
                if ( ! self::inject_pattern_covered( trim( $pattern ), $guard_paths ) ) {
                    $uncovered[] = trim( $pattern );
                }
            }

            $hint = ' Hinweis: Der Interceptor prüft ausschließlich den URL-Pfad bzw. den action-Namen — ein Handler an „init"/„admin_post", der beides ignoriert, läuft auch bei einem POST auf eine ungelistete URL.';

            if ( empty( $uncovered ) ) {
                $checks[] = [ 'check' => 'Inject-Pfade-Abdeckung', 'status' => 'ok', 'meldung' => 'jeder Inject-Pfad hat ein Gegenstück in „Geschützte Pfade".' . $hint ];
            } else {
                $checks[] = [
                    'check'   => 'Inject-Pfade-Abdeckung',
                    'status'  => 'warn',
                    'meldung' => sprintf(
                        'Auf diesen Inject-Pfaden wird die Sicherheitsabfrage angezeigt, aber von „Geschützte Pfade" nicht abgedeckt: %s. Das Formular sieht geschützt aus, der POST wird serverseitig nicht geprüft — Muster zusätzlich unter „Geschützte Pfade" (oder als Aktion unter „Geschützte Aktionen") eintragen.%s%s',
                        implode( ', ', $uncovered ),
                        empty( $guard_actions ) ? '' : ' (Es sind Aktionsmuster konfiguriert — falls das Formular über einen action-Namen läuft, kann es darüber abgedeckt sein.)',
                        $hint
                    ),
                ];
            }
        }

        // 16. Bestandskonfiguration aus früheren Versionen — die Eingabeprüfung
        //     dieser Version weist `0.0.0.0/0`/`::/0` in den Erlaubnis-/
        //     Vertrauenslisten (AF-5/CLI-1), einen `bypass_cookies`-Eintrag ohne
        //     Wert (BK-14) und ein Catch-all in `bypass_ua_allow` (BK-9) ab.
        //     Bereits gespeicherte Werte bleiben unangetastet — sie hier zu
        //     überschreiben hieße, eine laufende Installation ungefragt zu
        //     verändern. Deshalb: melden, nicht ändern. Zweiter Kanal derselben
        //     Erkennung ist die Admin-Notice (includes/hardening-migration.php).
        //
        //     Status `warn`, nicht `error`: `error` steuert den Exit-Code und
        //     ist in dieser Liste durchgehend für „die Installation kann so
        //     nicht arbeiten" reserviert (Bibliothek, Secrets, Tabelle,
        //     Extension). Ein gespeicherter Konfigurationswert ist etwas
        //     anderes — die Schwere trägt der Meldungstext, wie beim ebenso
        //     schutzaufhebenden `!`-Ausschlussmuster in Check 14.
        $hardening = function_exists( 'creationell_captcha_hardening_findings' )
            ? creationell_captcha_hardening_findings()
            : [];
        if ( empty( $hardening ) ) {
            $checks[] = [ 'check' => 'Bestandskonfiguration', 'status' => 'ok', 'meldung' => 'keine Alteinträge, die eine Erlaubnis-/Vertrauensliste aufheben oder einen Bypass ohne Geheimnis eintragen' ];
        } else {
            // Drei Zustände, drei Etiketten. „wirkt nicht mehr" pauschal für
            // alles Nicht-Aktive wäre falsch: ein Eintrag in einer Liste, deren
            // Funktion nur gerade ausgeschaltet ist (`ruhend`), wirkt sehr wohl
            // wieder — beim nächsten Einschalten, und dann sofort.
            $etiketten = [
                'aktiv'     => 'wirkt weiterhin',
                'unwirksam' => 'wirkt nicht mehr',
                'ruhend'    => 'wirkt, sobald die zugehörige Funktion eingeschaltet wird',
            ];
            $zeilen    = [];
            foreach ( $hardening as $finding ) {
                $zeilen[] = sprintf(
                    '%s „%s" [%s]: %s',
                    $finding['liste'],
                    $finding['eintrag'],
                    $etiketten[ $finding['wirkung'] ] ?? $finding['wirkung'],
                    $finding['meldung']
                );
            }
            $checks[] = [
                'check'   => 'Bestandskonfiguration',
                'status'  => 'warn',
                'meldung' => 'Diese Einträge stammen aus einer früheren Version und werden heute nicht mehr angenommen; gespeicherte Werte werden bewusst nicht überschrieben — '
                    . implode( ' | ', $zeilen ),
            ];
        }

        // 17. IPv4-mapped REMOTE_ADDR — Nachlese N2 / Cross-Strang-Hinweis aus F1
        //     (fix-F1-report.md, Bündel 4/I2). Die Kanonisierung in
        //     creationell_captcha_normalize_ip() repariert das Verhalten für
        //     IPv4-mapped Clients (`::ffff:a.b.c.d`, z. B. nginx mit
        //     `ipv6only=off`); sie macht aber nicht SICHTBAR, dass ein Server
        //     überhaupt in diese Klasse fällt — bis 1.1.0 griffen Blockliste,
        //     Erlaubnisliste, vertrauenswürdige Proxies und Watch-Liste für
        //     solche Clients NIE, ohne jede Meldung. Zwei Signale, weil WP-CLI
        //     normalerweise KEINE echte HTTP-Verbindung hat (REMOTE_ADDR ist
        //     unter der CLI-SAPI meist gar nicht gesetzt) — der Live-Wert ist
        //     also nur bei ungewöhnlichen Aufrufkontexten aussagekräftig, das
        //     Event-Log dagegen bei jeder Installation mit aktiver Protokollierung.
        $live_remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        $logged_mapped_ip  = null;
        if ( ! empty( $settings['analytics_event_log'] ) ) {
            $analytics_check17 = creationell_captcha_analytics();
            if ( $analytics_check17->table_exists() ) {
                foreach ( $analytics_check17->query_events( [ 'search' => '::ffff:', 'limit' => 5 ] ) as $row ) {
                    if ( isset( $row['ip'] ) && false !== stripos( (string) $row['ip'], '::ffff:' ) ) {
                        $logged_mapped_ip = (string) $row['ip'];
                        break;
                    }
                }
            }
        }
        $checks[] = self::mapped_remote_addr_check( $live_remote_addr, $logged_mapped_ip );

        // 18. CIDR-Einträge in IPv4-mapped-Notation — Nachlese N2 / Cross-Strang-
        //     Hinweis aus F1. creationell_captcha_normalize_ip() kanonisiert
        //     bewusst NUR einzelne Adressen, keine CIDR-Bereiche (ein
        //     Umrechnen der Präfixlänge könnte eine Trusted-Proxy-Zeile
        //     stillschweigend verbreitern — die verbotene Richtung, LK-13/AF-5).
        //     Ein vor 1.1.0 in mapped-Notation eingetragener CIDR-Bereich
        //     (`::ffff:203.0.113.0/120`) trifft seit 1.1.0 deshalb nicht mehr;
        //     der Betreiber soll das erfahren statt dass die Zeile still
        //     wirkungslos wird.
        $checks[] = self::mapped_cidr_check( $settings );

        // 19. Under-Attack-Pass-Rate — Cross-Strang-Hinweis N1 (nachlese-N1-report.md
        //     §3.3 „m4"/„m7"; `mint_pass()` in class-under-attack.php). Zwei Ursachen
        //     lassen mint_pass() dauerhaft null zurückgeben, sodass KEIN Besucher je
        //     das Gate passieren kann:
        //
        //     (a) Kein ableitbares HMAC-Secret. N1s Vorschlag ist die direkte
        //         Bedingung `creationell_captcha_derive_hmac_key(
        //         CREATIONELL_CAPTCHA_PURPOSE_UA_PASS ) === ''` -> `error` (Totalausfall,
        //         die Site liefert dauerhaft 503). Diese Funktion selbst wird hier
        //         bewusst NICHT aufgerufen: sie liest über
        //         creationell_captcha_get_hmac_secret() ->
        //         creationell_captcha_get_secret(), und Letztere heilt eine fehlende
        //         Option selbstheilend durch Neuerzeugen — ein Aufruf aus einem
        //         "doctor liest ausschließlich"-Kontext (Check 2) hätte also einen
        //         Schreib-Nebeneffekt. Stattdessen dieselbe seiteneffektfreie
        //         Auflösung wie Check 2 (Konstante ODER Option, ohne die Getter zu
        //         rufen) — ist die signature nicht auflösbar, ist auch die
        //         HMAC-Ableitung nicht möglich, und zwar unabhängig vom "purpose".
        //     (b) Ausgabe bereits vor `template_redirect` (headers_sent(), typischerweise
        //         ein BOM/Notice — laut N1 der alltägliche, gut erreichbare Fall). Von
        //         einem WP-CLI-Aufruf aus nicht direkt prüfbar (keine echte
        //         HTTP-Antwort) — deshalb misst der Fallback das SYMPTOM: viele
        //         "underattack"-Ereignisse ohne ein einziges "underattack_passed"-
        //         Ereignis ist genau das Bild, das (b) erzeugt (und auch (a), falls
        //         (a) nicht bereits gegriffen hat). Damit das Fehlen von Pässen
        //         aussagekräftig ist (statt "bisher hat es niemand versucht"), braucht
        //         es Event-Log, beide Log-Gates UND eine Mindestanzahl an Versuchen.
        if ( ! empty( $settings['underattack_enabled'] ) ) {
            $sig_resolvable = self::secret_resolvable(
                'CREATIONELL_CAPTCHA_HMAC_SECRET',
                get_option( 'creationell_captcha_secrets', [] ),
                'signature'
            );

            $pass_rate_data = null;
            if ( ! empty( $settings['analytics_event_log'] )
                && ! empty( $settings['log_underattack'] )
                && ! empty( $settings['log_underattack_passed'] )
            ) {
                $analytics_check19 = creationell_captcha_analytics();
                if ( $analytics_check19->table_exists() ) {
                    $pass_rate_data = [
                        'attempts' => $analytics_check19->count_events( [ 'event_type' => 'underattack' ] ),
                        'passed'   => $analytics_check19->count_events( [ 'event_type' => 'underattack_passed' ] ),
                    ];
                }
            }
            $checks[] = self::underattack_pass_rate_check( $sig_resolvable, $pass_rate_data );
        } else {
            $checks[] = [ 'check' => 'Under-Attack-Pass-Rate', 'status' => 'ok', 'meldung' => 'übersprungen (Under-Attack-Modus aus)' ];
        }

        // 20. Proxy-Header-Auswahl — Cross-Strang-Hinweis N1 ("m2"). Seit dieser
        //     Version ist `firewall_proxy_header` auf der Einstellungsseite ein
        //     Auswahlfeld mit vier bekannten Werten; ein davon abweichender
        //     gespeicherter Wert ist nur noch über einen Weg an der
        //     Einstellungsseite vorbei erreichbar (`wp option patch`,
        //     zurückgespieltes Backup, fremder update_option()-Aufruf).
        //     get_client_ip() fällt seit N1s Fix sicher auf x-forwarded-for zurück
        //     (Wahl UND Zerlegung zusammen) — vor diesem Fix führte ein solcher
        //     Wert dazu, dass eine echte XFF-Kette als EIN Wert ankam und JEDER
        //     Besucher als derselbe Client galt. Der Rückfall ist also nicht mehr
        //     akut gefährlich, aber weiterhin ein Konfigurationsfehler, den der
        //     Betreiber erfahren soll.
        $checks[] = self::proxy_header_choice_check( $settings );

        // 21. Under-Attack-Interstitial und Full-Page-Cache — Cross-Strang-Hinweis
        //     N1 ("m7", Kommentar in helpers.php beim ctx-Aussteller: "Making that
        //     visible is a `doctor` job"). Der einmalige `ctx`-Suppressions-Token
        //     ist an genau EINEN Abruf gebunden; eine von einem vollseitigen Cache
        //     oder CDN wiederholt ausgelieferte Kopie der 503-Seite übergibt dem
        //     (unsichtbaren) Widget einen bereits verbrauchten Token — der
        //     Besucher bekommt eine Bild-Eingabe, die er nie sieht, und kommt nicht
        //     durch. `nocache_headers()` sendet zwar bereits „no-store, private",
        //     aber ein Cache, der das ignoriert, ist von hier aus nicht zu
        //     verhindern. Drei Signale (N1 nennt alle drei in seinem Cross-Strang-
        //     Hinweis §3.3): bekannte WP-Cache-PLUGINS, die Konstante `WP_CACHE`
        //     (die praktisch jedes Cache-Plugin — auch eines, das nicht in der
        //     festen Liste steht — beim Aktivieren in wp-config.php setzt) und ein
        //     vorhandenes `advanced-cache.php`-Drop-in (das WP-Core selbst lädt,
        //     wenn `WP_CACHE` truthy ist). Ein vorgeschalteter CDN-/Reverse-Proxy-
        //     Cache (Cloudflare-Caching, Varnish o. Ä. ohne lokales Drop-in) bleibt
        //     für diesen Check dennoch unsichtbar, die Meldung sagt das offen.
        if ( ! empty( $settings['underattack_enabled'] ) ) {
            $cache_plugins = [
                'wp-super-cache/wp-cache.php'         => 'WP Super Cache',
                'w3-total-cache/w3-total-cache.php'   => 'W3 Total Cache',
                'wp-rocket/wp-rocket.php'              => 'WP Rocket',
                'litespeed-cache/litespeed-cache.php' => 'LiteSpeed Cache',
                'wp-fastest-cache/wpFastestCache.php' => 'WP Fastest Cache',
                'cache-enabler/cache-enabler.php'     => 'Cache Enabler',
                'sg-cachepress/sg-cachepress.php'     => 'SiteGround Optimizer (SG CachePress)',
            ];
            $active_cache_plugins = [];
            foreach ( $cache_plugins as $slug => $label ) {
                if ( is_plugin_active( $slug ) ) {
                    $active_cache_plugins[] = $label;
                }
            }
            $wp_cache_constant = defined( 'WP_CACHE' ) && \WP_CACHE;
            $advanced_cache_dropin = defined( 'WP_CONTENT_DIR' )
                && is_file( \WP_CONTENT_DIR . '/advanced-cache.php' );
            $checks[] = self::underattack_cache_check( $active_cache_plugins, $wp_cache_constant, $advanced_cache_dropin );
        } else {
            $checks[] = [ 'check' => 'Under-Attack-Interstitial und Full-Page-Cache', 'status' => 'ok', 'meldung' => 'übersprungen (Under-Attack-Modus aus)' ];
        }

        // 22. Aufbewahrungsfrist bei gesetztem Kill-Switch — Nachlese N6
        //     (Befund 6). W3-2 hat den Kill-Switch-Guard in
        //     Analytics::ensure_prune_schedule() UND run_scheduled_prune()
        //     eingebaut: „aus" soll auch „löscht nichts" heissen, damit ein
        //     Betreiber, der während eines Vorfalls CREATIONELL_CAPTCHA_DISABLE
        //     setzt, den Zustand wirklich einfriert. Diese Begründung trägt für
        //     den kurzen Einsatz — nicht für eine Konstante, die länger steht
        //     als die Aufbewahrungsdauer (Staging-Konfiguration, die auf die
        //     Produktion kopiert wurde; „Plugin funktional aus" statt
        //     Deaktivierung). Dann läuft die Frist nie ab, obwohl die
        //     Einstellung sie zusagt — und genau dafür war der Sweep gebaut
        //     (DS-1: „a switched-off log is precisely the case that needs it").
        //     Der Guard bleibt, der Zustand wird gemeldet: `wp creacaptcha log
        //     prune` läuft unabhängig vom Kill-Switch und ist der Weg heraus.
        $checks[] = self::retention_sweep_check(
            creationell_captcha_is_disabled(),
            creationell_captcha_analytics()->table_exists(),
            (int) ( $settings['analytics_log_retention'] ?? 30 )
        );

        /**
         * Filters the doctor-checklist. Third-party modules can append their
         * own checks. Each entry must follow the shape
         * `['check' => string, 'status' => 'ok'|'warn'|'error', 'meldung' => string]`.
         */
        $checks = (array) apply_filters( 'creationell_captcha_doctor_checks', $checks );

        $has_error = false;
        foreach ( $checks as $row ) {
            if ( 'error' === ( $row['status'] ?? '' ) ) {
                $has_error = true;
                break;
            }
        }

        \WP_CLI\Utils\format_items( $format, $checks, [ 'check', 'status', 'meldung' ] );

        if ( $has_error ) {
            WP_CLI::halt( 1 );
        }
    }

    /**
     * Check 4 — Cloudflare-Refresh-Cron.
     *
     * B-I4: the auto-refresh cron slot is only ever scheduled when BOTH
     * `firewall_trust_cloudflare` AND `firewall_cloudflare_auto_refresh` are
     * on (`creationell_captcha_sync_cloudflare_cron()`,
     * cloudflare-proxies.php:173-176) — reading `firewall_cloudflare_auto_refresh`
     * alone made this check report a permanent `error` on a healthy install
     * whose proxy mode is off but whose two dependent fields are still frozen
     * `true` by the settings requires-rewrite (they are simply gated, not
     * broken). Mirrors the exact condition `sync_cloudflare_cron()` uses, and
     * downgrades the "gated" case to `warn` — the field not taking effect is
     * expected, not a defect.
     *
     * @param array<string, mixed> $settings      Current plugin settings.
     * @param int|false            $next_scheduled Return value of
     *                                              `wp_next_scheduled('creationell_captcha_refresh_cloudflare_ips')`.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function cloudflare_cron_check( array $settings, $next_scheduled ): array {
        $enabled = ! empty( $settings['firewall_trust_cloudflare'] )
            && ! empty( $settings['firewall_cloudflare_auto_refresh'] );

        if ( ! $enabled ) {
            return [ 'check' => 'Cloudflare-Refresh-Cron', 'status' => 'ok', 'meldung' => 'übersprungen (Cloudflare-Vertrauen oder auto-refresh aus)' ];
        }

        if ( false !== $next_scheduled ) {
            return [ 'check' => 'Cloudflare-Refresh-Cron', 'status' => 'ok', 'meldung' => sprintf( 'geplant für %s UTC', gmdate( 'Y-m-d H:i:s', (int) $next_scheduled ) ) ];
        }

        if ( empty( $settings['firewall_behind_proxy'] ) ) {
            return [
                'check'   => 'Cloudflare-Refresh-Cron',
                'status'  => 'warn',
                'meldung' => 'Cloudflare-Vertrauen und auto-refresh sind gesetzt, aber der Proxy-Modus ist aus — beide Werte sind dadurch gegatet und wirken nicht (kein Cron geplant, korrekt so). Proxy-Modus einschalten oder die beiden Felder zurücksetzen.',
            ];
        }

        return [
            'check'   => 'Cloudflare-Refresh-Cron',
            'status'  => 'error',
            'meldung' => 'auto-refresh aktiv, aber kein Cron geplant — Settings einmal speichern oder `wp cron event schedule` aufrufen.',
        ];
    }

    /**
     * Ableitung zu Check 2 und Check 19 — löst EIN Secret aus seinen beiden
     * Quellen auf, ohne die Getter zu rufen.
     *
     * Bis zum Re-Review stand diese Disjunktion inline in run(); die
     * Doctor-Suite ruft aber ausschliesslich die reinen Check-Funktionen mit
     * bereits fertigen Argumenten auf, sodass eine Ruecknahme des
     * Konstanten-Zweigs von KEINEM Test bemerkt wurde (Fehlerklasse 2: der Fix
     * stimmt, der Beweis trifft den Pfad nicht). Als eigener Helfer ist die
     * B-M22-Divergenz — Konstante gesetzt, Option leer — direkt und
     * diskriminierend pruefbar.
     *
     * Der Konstantenname kommt als Zeichenkette herein, damit ein Test beide
     * Zweige im selben Prozess durchlaufen kann; `constant()` liest ihn erst
     * nach dem `defined()`-Guard.
     *
     * Bewusst NICHT ueber creationell_captcha_get_hmac_secret(): der Getter
     * heilt eine fehlende Option durch Neuerzeugen und PERSISTIEREN — ein
     * Schreibvorgang, den diese rein lesende Diagnose nie ausloesen darf
     * (Vertrag „doctor liest ausschliesslich" im Klassen-Docblock).
     *
     * @param string $constant       Name der wp-config-Konstante (Vorrang).
     * @param mixed  $secrets_option Inhalt der Option `creationell_captcha_secrets` (Rueckfall).
     * @param string $option_key     Schluessel innerhalb dieser Option.
     */
    public static function secret_resolvable( string $constant, mixed $secrets_option, string $option_key ): bool {
        if ( defined( $constant ) ) {
            $value = constant( $constant );
            if ( is_string( $value ) && '' !== $value ) {
                return true;
            }
        }

        return is_array( $secrets_option ) && ! empty( $secrets_option[ $option_key ] );
    }

    /**
     * Ableitung zu Check 9 / CLI-10 — der sanitisierte Vergleichsstand.
     *
     * Ruft den Sanitizer im PROGRAMMATIC-Kontext NUR zum Vergleichen auf und
     * schreibt das Ergebnis nicht. Seit Welle 1 ist der Sanitizer
     * seiteneffektfrei (der ensure_table()-Aufruf haengt an den
     * update_option_/add_option_-Hooks, nicht mehr am Sanitizer), sonst waere
     * dieser Aufruf aus einer rein lesenden Diagnose heraus unzulaessig.
     *
     * Eigener Helfer aus demselben Grund wie secret_resolvable(): stand diese
     * Zeile inline in run(), liess sich der Wertvergleich auf `$sanitized =
     * $stored` zuruecknehmen, ohne dass eine Suite rot wurde — Check 9 haette
     * dann strukturell nie eine Wertabweichung sehen koennen.
     *
     * @param array<string, mixed> $stored Gespeicherter Wertesatz.
     * @return array<string, mixed> Der sanitisierte Wertesatz.
     */
    public static function sanitized_snapshot( array $stored ): array {
        return creationell_captcha_sanitize_settings( $stored, \CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC );
    }

    /**
     * Ableitung zu Check 11 — B-I7.
     *
     * Die Substanz des B-I7-Fixes ist die QUELLE des dritten Arguments:
     * `creationell_captcha_wc_login_active()` statt des rohen Toggles
     * `$settings['protect_wc_login']`. Genau diese Wahl lag inline in run()
     * und war deshalb von keiner Suite bewacht — login_coverage_check() selbst
     * bekommt den Wert ja fertig gereicht. Als eigener Helfer ist der
     * eingefrorene Fall (protect_wc_login = true bei ausgeschaltetem Master
     * protect_woocommerce, AF-1) direkt pruefbar.
     *
     * @param array<string, mixed> $settings Aktueller Wertesatz.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function login_coverage_row( array $settings ): array {
        return self::login_coverage_check(
            $settings,
            class_exists( 'WooCommerce' ),
            creationell_captcha_wc_login_active()
        );
    }

    /**
     * Check 2 — HMAC-Secrets.
     *
     * B-M22: signature and key-signature each resolve independently — a site can set
     * one wp-config constant and rely on the stored option for the other. Missing
     * either one leaves the engine unable to sign/verify challenges, so `error` (not
     * `warn`) is correct here, matching the `error`-Regel in Check 16's comment.
     *
     * @param bool $sig_resolved Whether the signature secret resolves (constant or option).
     * @param bool $key_resolved Whether the key-signature secret resolves (constant or option).
     * @return array{check: string, status: string, meldung: string}
     */
    public static function hmac_secrets_check( bool $sig_resolved, bool $key_resolved ): array {
        if ( $sig_resolved && $key_resolved ) {
            return [ 'check' => 'HMAC-Secrets', 'status' => 'ok', 'meldung' => 'gesetzt (Konstante oder Option)' ];
        }

        $missing = [];
        if ( ! $sig_resolved ) {
            $missing[] = 'signature (CREATIONELL_CAPTCHA_HMAC_SECRET oder Option)';
        }
        if ( ! $key_resolved ) {
            $missing[] = 'key_signature (CREATIONELL_CAPTCHA_HMAC_KEY_SECRET oder Option)';
        }

        return [
            'check'   => 'HMAC-Secrets',
            'status'  => 'error',
            'meldung' => sprintf(
                'Fehlt: %s — `wp creacaptcha repair` ausführen (legt eine fehlende Option neu an; hat keine Wirkung, wenn bereits eine wp-config-Konstante gesetzt ist und nur die andere Hälfte fehlt).',
                implode( ', ', $missing )
            ),
        ];
    }

    /**
     * Check 9 — Settings-Defaults-Vollstaendigkeit + CLI-10-Wertspezifikation.
     *
     * Nachlese N2: schliesst die CLI-10-Grenze ("nur die Schluesselmenge"), seit der
     * Sanitizer-Aufruf selbst kein DDL mehr ausloest (Welle 1). `$sanitized` ist der
     * Aufrufer-seitige, rein lesende Sanitizer-Durchlauf ueber `$stored`
     * (`creationell_captcha_sanitize_settings($stored, CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC)`)
     * — diese Methode selbst ruft ihn nicht auf und bleibt dadurch ohne jede
     * settings.php-Abhaengigkeit direkt testbar.
     *
     * @param array<string, mixed> $defaults  `creationell_captcha_get_default_settings()`.
     * @param array<string, mixed> $stored    Roher Optionswert.
     * @param array<string, mixed> $sanitized `$stored` durch den Sanitizer geschickt (PROGRAMMATIC, nicht geschrieben).
     * @return array{check: string, status: string, meldung: string}
     */
    public static function settings_defaults_check( array $defaults, array $stored, array $sanitized ): array {
        $missing = array_diff_key( $defaults, $stored );

        $mismatched = [];
        foreach ( $stored as $key => $value ) {
            if ( array_key_exists( $key, $sanitized ) && $sanitized[ $key ] !== $value ) {
                $mismatched[] = (string) $key;
            }
        }

        if ( empty( $missing ) && empty( $mismatched ) ) {
            return [
                'check'   => 'Settings-Defaults',
                'status'  => 'ok',
                'meldung' => 'alle Schlüssel vorhanden, alle Werte entsprechen der Feldspezifikation (Sanitizer-Vergleich, rein lesend).',
            ];
        }

        $parts = [];
        if ( ! empty( $missing ) ) {
            $parts[] = sprintf(
                '%d Schlüssel fehlen (%s)',
                count( $missing ),
                implode( ', ', array_slice( array_keys( $missing ), 0, 5 ) )
            );
        }
        if ( ! empty( $mismatched ) ) {
            $parts[] = sprintf(
                '%d Wert(e) weichen von der Feldspezifikation ab (%s) — vermutlich an den Plugin-Schreibwegen vorbei gesetzt (z. B. `wp option patch`)',
                count( $mismatched ),
                implode( ', ', array_slice( $mismatched, 0, 5 ) )
            );
        }

        return [
            'check'   => 'Settings-Defaults',
            'status'  => 'warn',
            'meldung' => implode( '; ', $parts ) . ' — `wp creacaptcha repair` ausführen oder Einstellungen einmal speichern.',
        ];
    }

    /**
     * Check 7b — Sodium-Extension (für Argon2id-Algorithmus erforderlich).
     *
     * B-I5: `Engine::algorithm_key()` (class-engine.php:601-611) falls back to
     * PBKDF2 silently and logs when `ext-sodium` is missing — challenges keep
     * working. That is a working degradation, not the "cannot work" state
     * `error` is reserved for (see the Check-16 comment below), so this is
     * `warn`.
     *
     * @param array<string, mixed> $settings         Current plugin settings.
     * @param bool                 $sodium_available Result of `creationell_captcha_sodium_available()`.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function sodium_check( array $settings, bool $sodium_available ): array {
        if ( 'argon2id' !== ( $settings['algorithm'] ?? '' ) ) {
            return [ 'check' => 'Sodium-Extension', 'status' => 'ok', 'meldung' => 'übersprungen (Algorithmus ist PBKDF2)' ];
        }

        return $sodium_available
            ? [ 'check' => 'Sodium-Extension', 'status' => 'ok', 'meldung' => 'verfügbar (für Argon2id)' ]
            : [
                'check'   => 'Sodium-Extension',
                'status'  => 'warn',
                'meldung' => 'fehlt — Argon2id ist konfiguriert, die Engine fällt beim Lösen still auf PBKDF2 zurück (Engine::algorithm_key()); Challenges funktionieren weiterhin. PBKDF2 wählen oder ext-sodium installieren, um die konfigurierte Stärke tatsächlich zu nutzen.',
            ];
    }

    /**
     * Check 10 — PHP-GD-Extension (für Code-Challenge erforderlich).
     *
     * B-I5: fehlendes GD lässt `should_issue_code_challenge()`
     * (code-challenge.php:31-33) die Zusatzstufe grundsätzlich nie auslösen —
     * die PoW-Stufe bleibt unverändert aktiv, nichts fällt aus. Working
     * degradation statt Ausfall, also `warn` statt `error` (siehe Check 16).
     *
     * @param array<string, mixed> $settings  Current plugin settings.
     * @param bool                 $gd_loaded Result of `extension_loaded('gd')`.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function gd_check( array $settings, bool $gd_loaded ): array {
        if ( empty( $settings['code_challenge_enabled'] ) ) {
            return [ 'check' => 'PHP-GD-Extension', 'status' => 'ok', 'meldung' => 'übersprungen (Code-Challenge aus)' ];
        }

        return $gd_loaded
            ? [ 'check' => 'PHP-GD-Extension', 'status' => 'ok', 'meldung' => 'verfügbar (für Code-Challenge)' ]
            : [
                'check'   => 'PHP-GD-Extension',
                'status'  => 'warn',
                'meldung' => 'fehlt — Code-Challenge ist konfiguriert, aber should_issue_code_challenge() schaltet die Bild-Zusatzstufe dadurch automatisch ab; die PoW-Stufe bleibt unverändert aktiv. GD installieren, um die Bild-Eingabe wieder auszuspielen.',
            ];
    }

    /**
     * Check 11 — Login-Formular-Abdeckung.
     *
     * B-I7: reading `protect_wc_login` raw ignored the kill switch and the
     * `protect_woocommerce` master toggle — a value frozen `true` by the
     * settings requires-rewrite from a time when Woo protection was on kept
     * reporting "ok" long after `protect_woocommerce` was switched off, hiding
     * the exact IN-7 gap (My-Account login unprotected) this check exists to
     * surface. `creationell_captcha_wc_login_active()` is the single source
     * of truth the render/verify hooks themselves use.
     *
     * @param array<string, mixed> $settings              Current plugin settings.
     * @param bool                 $woocommerce_installed Result of `class_exists('WooCommerce')`.
     * @param bool                 $wc_login_active       Result of `creationell_captcha_wc_login_active()`.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function login_coverage_check( array $settings, bool $woocommerce_installed, bool $wc_login_active ): array {
        if ( empty( $settings['protect_login'] ) ) {
            return [ 'check' => 'Login-Formular-Abdeckung', 'status' => 'ok', 'meldung' => 'übersprungen (protect_login aus)' ];
        }

        $meldung = 'aktiv: /wp-login.php + wp_login_form()-basierte Theme-/Widget-Logins.';

        if ( $woocommerce_installed && ! $wc_login_active ) {
            return [
                'check'   => 'Login-Formular-Abdeckung',
                'status'  => 'warn',
                'meldung' => $meldung . ' WooCommerce-My-Account-Login ist davon NICHT erfasst (eigenes Formular, andere Feldnamen) — „WooCommerce schützen" → „My-Account-Login schützen" separat aktivieren, falls gewünscht.',
            ];
        }

        return [ 'check' => 'Login-Formular-Abdeckung', 'status' => 'ok', 'meldung' => $meldung ];
    }

    /**
     * Check 17 — IPv4-mapped REMOTE_ADDR (Cross-Strang-Hinweis F1, Bündel 4/I2).
     *
     * Zwei unabhängige Signale, weil ein `wp`-Aufruf über die CLI-SAPI normalerweise
     * KEINE echte HTTP-Verbindung hat: `$_SERVER['REMOTE_ADDR']` ist unter WP-CLI
     * meist gar nicht gesetzt, ein Live-Treffer also nur bei ungewöhnlichen
     * Aufrufkontexten möglich. Das Event-Log ist die verlässlichere Quelle: da
     * `creationell_captcha_get_client_ip()` seit 1.1.0 jede IP kanonisiert, BEVOR sie
     * geloggt wird, kann eine `::ffff:`-Adresse im Log nur aus der Zeit VOR dem
     * Update stammen — ein direkter, installationsspezifischer Nachweis, dass dieser
     * Server REMOTE_ADDR mindestens zeitweise mapped ausliefert.
     *
     * @param string      $live_remote_addr `$_SERVER['REMOTE_ADDR']` bei diesem Aufruf, oder ''.
     * @param string|null $logged_mapped_ip Eine im Event-Log gefundene mapped-Adresse, oder null.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function mapped_remote_addr_check( string $live_remote_addr, ?string $logged_mapped_ip ): array {
        if ( '' !== $live_remote_addr && $live_remote_addr !== creationell_captcha_normalize_ip( $live_remote_addr ) ) {
            return [
                'check'   => 'IPv4-mapped REMOTE_ADDR',
                'status'  => 'warn',
                'meldung' => sprintf(
                    'Dieser Aufruf sieht REMOTE_ADDR als „%s" (IPv4-mapped, typisch für nginx mit „ipv6only=off"). Seit 1.1.0 werden solche Adressen für IP-Blockliste, IP-Erlaubnisliste, vertrauenswürdige Proxies und die Watch-Liste kanonisiert; davor griffen diese Listen für solche Clients NIE.',
                    $live_remote_addr
                ),
            ];
        }

        if ( null !== $logged_mapped_ip ) {
            return [
                'check'   => 'IPv4-mapped REMOTE_ADDR',
                'status'  => 'warn',
                'meldung' => sprintf(
                    'REMOTE_ADDR ist bei diesem Aufruf nicht direkt prüfbar (WP-CLI hat i. d. R. keine echte Client-Verbindung), aber das Event-Log enthält eine ältere Zeile mit IPv4-mapped-Adresse „%s" — dieser Server liefert REMOTE_ADDR mindestens zeitweise in dieser Form. Bis 1.1.0 griffen IP-Blockliste, IP-Erlaubnisliste, vertrauenswürdige Proxies und die Watch-Liste für solche Clients NIE; betroffen sind nur Zeilen VOR dem Update auf 1.1.0, neue Zeilen zeigen die kanonisierte Form.',
                    $logged_mapped_ip
                ),
            ];
        }

        return [
            'check'   => 'IPv4-mapped REMOTE_ADDR',
            'status'  => 'ok',
            'meldung' => 'kein Hinweis auf IPv4-mapped REMOTE_ADDR (weder bei diesem Aufruf noch im Event-Log — Letzteres nur aussagekräftig, wenn das Event-Log aktiv ist und ausreichend lange mitgeschrieben hat).',
        ];
    }

    /**
     * Check 18 — CIDR-Einträge in IPv4-mapped-Notation (Cross-Strang-Hinweis F1).
     *
     * `creationell_captcha_normalize_ip()` (helpers.php) kanonisiert bewusst nur
     * einzelne Adressen, nie CIDR-Bereiche — ein Umrechnen der Präfixlänge könnte
     * eine Trusted-Proxy-Zeile stillschweigend verbreitern. Ein vor 1.1.0 in mapped
     * Notation eingetragener Bereich (`::ffff:203.0.113.0/120`) trifft seit 1.1.0
     * deshalb nicht mehr; dieser Check macht das sichtbar statt es still wirkungslos
     * werden zu lassen.
     *
     * @param array<string, mixed> $settings Current plugin settings.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function mapped_cidr_check( array $settings ): array {
        $lists = [
            'IP-Blockliste'              => (array) ( $settings['firewall_ip_block'] ?? [] ),
            'IP-Erlaubnisliste'          => (array) ( $settings['firewall_ip_allow'] ?? [] ),
            'Vertrauenswürdige Proxies'  => (array) ( $settings['firewall_trusted_proxies'] ?? [] ),
            'Watch-Liste (Bild-Code)'    => (array) ( $settings['code_challenge_watchlist'] ?? [] ),
        ];

        $offenders = [];
        foreach ( $lists as $label => $entries ) {
            foreach ( $entries as $raw ) {
                $entry = trim( (string) $raw );
                if ( self::is_mapped_cidr( $entry ) ) {
                    $offenders[] = sprintf( '%s: „%s"', $label, $entry );
                }
            }
        }

        if ( empty( $offenders ) ) {
            return [
                'check'   => 'CIDR in IPv4-mapped-Notation',
                'status'  => 'ok',
                'meldung' => 'kein Listeneintrag verwendet eine IPv4-mapped-CIDR-Schreibweise (::ffff:a.b.c.d/N).',
            ];
        }

        return [
            'check'   => 'CIDR in IPv4-mapped-Notation',
            'status'  => 'warn',
            'meldung' => 'Diese CIDR-Einträge stehen in IPv4-mapped-Notation und treffen seit 1.1.0 NICHT mehr (bewusst — ein Umrechnen der Präfixlänge könnte eine Trusted-Proxy-Zeile stillschweigend verbreitern): '
                . implode( ', ', $offenders )
                . '. Zeile auf reines IPv4- bzw. reines IPv6-CIDR umschreiben (Beispiel: „::ffff:203.0.113.0/120" → „203.0.113.0/24").',
        ];
    }

    /**
     * Whether a CIDR range's subnet part is written in IPv4-mapped notation
     * (`::ffff:a.b.c.d/N` — RFC 4291 §2.5.5.2), the one shape
     * `creationell_captcha_normalize_ip()` deliberately does not touch (see Check
     * 18's docblock). Mirrors that function's binary-form check, scoped to the
     * subnet segment of a CIDR entry instead of a plain address.
     *
     * @param string $entry One list entry, already trimmed.
     */
    private static function is_mapped_cidr( string $entry ): bool {
        if ( ! str_contains( $entry, '/' ) ) {
            return false;
        }

        [ $subnet ] = explode( '/', $entry, 2 );
        $bin        = @inet_pton( trim( $subnet ) );
        if ( false === $bin || 16 !== strlen( $bin ) ) {
            return false;
        }

        return "\0\0\0\0\0\0\0\0\0\0\xff\xff" === substr( $bin, 0, 12 );
    }

    /**
     * Check 19 — Under-Attack-Pass-Rate (Cross-Strang-Hinweis N1, "m4"/"m7").
     *
     * Two independent signals, checked in order of confidence:
     *
     * 1. `$sig_resolvable` false — no HMAC signature secret resolves (neither the
     *    wp-config constant nor the stored option), so `mint_pass()` cannot derive a
     *    token for ANY visitor. This is N1's suggested direct condition
     *    (`creationell_captcha_derive_hmac_key(...) === ''`), reformulated without
     *    calling the self-healing getter chain (see the `__invoke()` comment above
     *    this call) — `error`, because the site is durably unusable, matching the
     *    `error`-reservation rule from Check 16's comment.
     * 2. `$data` — the event-log symptom (see below), for the other cause
     *    (`headers_sent()`), which cannot be observed directly from a WP-CLI process.
     *
     * `$data` is null when the prerequisites for a meaningful measurement are not
     * met (event log off, either log gate off, or the table missing) — reported as
     * "not measurable", never as "ok" by absence of evidence. Below the attempt
     * threshold the same applies: zero passes out of zero or a handful of attempts
     * says nothing about whether the gate is passable at all.
     *
     * @param bool                                    $sig_resolvable Whether the HMAC
     *                                                                signature secret
     *                                                                resolves (constant
     *                                                                or option).
     * @param array{attempts: int, passed: int}|null $data Event counts, or null if unmeasurable.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function underattack_pass_rate_check( bool $sig_resolvable, ?array $data ): array {
        if ( ! $sig_resolvable ) {
            return [
                'check'   => 'Under-Attack-Pass-Rate',
                'status'  => 'error',
                'meldung' => 'Kein HMAC-Secret ableitbar (weder CREATIONELL_CAPTCHA_HMAC_SECRET noch die Option creationell_captcha_secrets liefern einen Wert) — der Under-Attack-Pass kann für KEINEN Besucher ausgestellt werden, die Site bleibt dauerhaft auf HTTP 503. `wp creacaptcha repair` ausführen.',
            ];
        }

        if ( null === $data ) {
            return [
                'check'   => 'Under-Attack-Pass-Rate',
                'status'  => 'ok',
                'meldung' => 'HMAC-Secret ist ableitbar; die Pass-Rate selbst ist nicht messbar (Event-Log, „Under-Attack protokollieren" oder „Under-Attack-Bestehen protokollieren" sind aus, oder die Tabelle fehlt).',
            ];
        }

        // Under threshold, no attempts have accumulated yet — "0 von 0" would read
        // like a broken gate on a brand-new installation that nobody has hit yet.
        $threshold = 5;
        if ( $data['attempts'] < $threshold ) {
            return [
                'check'   => 'Under-Attack-Pass-Rate',
                'status'  => 'ok',
                'meldung' => sprintf( 'zu wenige Versuche bisher (%d von %d nötig) für eine aussagekräftige Messung.', $data['attempts'], $threshold ),
            ];
        }

        if ( $data['passed'] > 0 ) {
            return [
                'check'   => 'Under-Attack-Pass-Rate',
                'status'  => 'ok',
                'meldung' => sprintf( '%d von %d protokollierten Anfragen haben das Gate bestanden — Pass-Vergabe funktioniert.', $data['passed'], $data['attempts'] ),
            ];
        }

        return [
            'check'   => 'Under-Attack-Pass-Rate',
            'status'  => 'warn',
            'meldung' => sprintf(
                '%d protokollierte Under-Attack-Anfragen, aber KEINE einzige hat das Gate bestanden — niemand kann derzeit durchkommen. Das HMAC-Secret ist ableitbar (siehe oben), die verbleibende bekannte Ursache (loggt unter CREATIONELL_CAPTCHA_DEBUG): Ausgabe wird bereits vor „template_redirect" gesendet — ein BOM in einer Theme-Datei, ein Notice mit display_errors an, ein frühes echo auf init.',
                $data['attempts']
            ),
        ];
    }

    /**
     * Check 20 — Proxy-Header-Auswahl (Cross-Strang-Hinweis N1, "m2").
     *
     * The four values mirror the `firewall_proxy_header` select field's options in
     * `includes/settings.php` (and `creationell_captcha_get_client_ip()`'s
     * `$header_map` in `includes/helpers.php`) — kept in sync manually since this
     * check must not depend on either of those files loading.
     *
     * @param array<string, mixed> $settings Current plugin settings.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function proxy_header_choice_check( array $settings ): array {
        if ( empty( $settings['firewall_behind_proxy'] ) ) {
            return [ 'check' => 'Proxy-Header-Auswahl', 'status' => 'ok', 'meldung' => 'übersprungen (Proxy-Modus aus)' ];
        }

        $known  = [ 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'true-client-ip' ];
        $choice = (string) ( $settings['firewall_proxy_header'] ?? 'x-forwarded-for' );

        if ( in_array( $choice, $known, true ) ) {
            return [ 'check' => 'Proxy-Header-Auswahl', 'status' => 'ok', 'meldung' => sprintf( '„%s" — bekannter Wert.', $choice ) ];
        }

        return [
            'check'   => 'Proxy-Header-Auswahl',
            'status'  => 'warn',
            'meldung' => sprintf(
                'firewall_proxy_header steht auf „%s" — kein bekannter Wert (die Einstellungsseite bietet seit dieser Version nur noch x-forwarded-for, x-real-ip, cf-connecting-ip, true-client-ip an; erreichbar also nur an der Einstellungsseite vorbei, z. B. `wp option patch`). Fällt zur Laufzeit sicher auf x-forwarded-for zurück — bitte den Wert trotzdem auf einen der vier bekannten umstellen.',
                $choice
            ),
        ];
    }

    /**
     * Check 21 — Under-Attack-Interstitial und Full-Page-Cache (Cross-Strang-Hinweis
     * N1, "m7", §3.3 — nennt alle drei hier verwendeten Signale ausdrücklich).
     *
     * @param array<int, string> $active_cache_plugins  Labels of active known caching plugins.
     * @param bool               $wp_cache_constant     Whether `WP_CACHE` is defined and truthy.
     * @param bool               $advanced_cache_dropin Whether `wp-content/advanced-cache.php` exists.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function underattack_cache_check(
        array $active_cache_plugins,
        bool $wp_cache_constant,
        bool $advanced_cache_dropin
    ): array {
        if ( empty( $active_cache_plugins ) && ! $wp_cache_constant && ! $advanced_cache_dropin ) {
            return [
                'check'   => 'Under-Attack-Interstitial und Full-Page-Cache',
                'status'  => 'ok',
                'meldung' => 'kein bekanntes WP-Cache-Plugin aktiv, WP_CACHE ist nicht gesetzt, kein advanced-cache.php-Drop-in gefunden. Ein vorgeschalteter CDN-/Reverse-Proxy-Cache ohne lokales Drop-in bleibt für diesen Check dennoch unsichtbar.',
            ];
        }

        $signals = $active_cache_plugins;
        if ( $wp_cache_constant ) {
            $signals[] = 'WP_CACHE ist gesetzt';
        }
        if ( $advanced_cache_dropin ) {
            $signals[] = 'advanced-cache.php-Drop-in vorhanden';
        }

        return [
            'check'   => 'Under-Attack-Interstitial und Full-Page-Cache',
            'status'  => 'warn',
            'meldung' => sprintf(
                'Hinweise auf Full-Page-Caching: %s. Die 503-Interstitial-Seite trägt einen einmaligen Suppressions-Token (ctx) für die Bild-Code-Stufe — wird die Seite aus dem Cache erneut ausgeliefert, bekommt das unsichtbare Widget einen bereits verbrauchten Token und der Besucher kommt nicht durch. Die Seite sendet „no-store, private" (nocache_headers()); bitte prüfen, dass die 503-Antwort bzw. der Pfad des Under-Attack-Modus vom Caching ausgenommen ist.',
                implode( ', ', $signals )
            ),
        ];
    }

    /**
     * Check 22 — läuft die Aufbewahrungsfrist des Event-Logs überhaupt?
     *
     * Nachlese N6, Befund 6. `Analytics::run_scheduled_prune()` und
     * `ensure_prune_schedule()` steigen seit W3-2 beim Kill-Switch sofort aus.
     * Für den kurzen Einsatz ist das richtig — Zeilen zu löschen ist die
     * einzige zerstörende Hintergrundoperation dieses Plugins, und wer während
     * eines Vorfalls `CREATIONELL_CAPTCHA_DISABLE` setzt, will den Zustand
     * einfrieren, nicht die Beweise wegräumen lassen. Für eine Konstante, die
     * länger steht als die Aufbewahrungsdauer, ist es eine offene Zusage: die
     * Einstellung sagt „ältere Einträge werden entfernt", und es passiert
     * nichts. Der Guard bleibt (dieselbe Entscheidung wie in W3-2), aber der
     * Zustand wird gemeldet statt still zu bleiben.
     *
     * `wp creacaptcha log prune` prüft den Kill-Switch NICHT und ist damit der
     * Weg heraus, ohne die Konstante anzufassen — die Meldung nennt ihn.
     *
     * @param bool $disabled      Whether the wp-config kill switch is set.
     * @param bool $table_exists  Whether the event-log table is present.
     * @param int  $retention_days Configured retention window in days.
     * @return array{check: string, status: string, meldung: string}
     */
    public static function retention_sweep_check( bool $disabled, bool $table_exists, int $retention_days ): array {
        if ( ! $disabled ) {
            return [
                'check'   => 'Aufbewahrungsfrist des Event-Logs',
                'status'  => 'ok',
                'meldung' => sprintf( 'läuft täglich (%d Tage).', $retention_days ),
            ];
        }

        if ( ! $table_exists ) {
            return [
                'check'   => 'Aufbewahrungsfrist des Event-Logs',
                'status'  => 'ok',
                'meldung' => 'übersprungen (keine Ereignistabelle vorhanden).',
            ];
        }

        return [
            'check'   => 'Aufbewahrungsfrist des Event-Logs',
            'status'  => 'warn',
            'meldung' => sprintf(
                'CREATIONELL_CAPTCHA_DISABLE ist gesetzt — der tägliche Durchlauf löscht nichts, obwohl die Ereignistabelle vorhanden ist und die Einstellung %d Tage zusagt. Gedacht ist das für den kurzen Einsatz während eines Vorfalls (Zustand einfrieren). Steht die Konstante länger als die Aufbewahrungsdauer, altern die gespeicherten IP-Adressen, User-Agents und Referrer nicht mehr aus: `wp creacaptcha log prune` räumt einmalig auf und prüft den Kill-Switch nicht.',
                $retention_days
            ),
        ];
    }

    /**
     * The interceptor's own guard lists, run through the SAME filters
     * `Interceptor::is_guarded()`/`action_patterns()` apply at runtime
     * (`creationell_captcha_interceptor_paths` / `_actions`).
     *
     * W1-9: checks 14 and 15 used to read `$settings['interceptor_paths']`/
     * `['interceptor_actions']` directly. That is not what the interceptor
     * itself decides on — a site using the documented
     * `creationell_captcha_protect_path()` developer API only ever touches
     * these filters, never the settings option, so the raw read was blind to
     * filter-added guards (false "uncovered"/"ok, no exclusion problem") and
     * equally blind to a filter that REMOVES a settings entry.
     *
     * Public and static so the filter wiring itself — not just what the
     * downstream checks do with the result — can be exercised directly in
     * `tests/test-cli-doctor-checks.php`.
     *
     * @param array<string, mixed> $settings Current plugin settings.
     * @return array{paths: array<int, string>, actions: array<int, string>}
     */
    public static function filtered_interceptor_lists( array $settings ): array {
        return [
            'paths'   => (array) apply_filters(
                'creationell_captcha_interceptor_paths',
                (array) ( $settings['interceptor_paths'] ?? [] )
            ),
            'actions' => (array) apply_filters(
                'creationell_captcha_interceptor_actions',
                (array) ( $settings['interceptor_actions'] ?? [] )
            ),
        ];
    }

    /**
     * Check 15 — whether a single inject-path pattern has a real counterpart
     * in the guard list.
     *
     * Fixes two bugs found for this check (Bündel 5 / W1-10, W1-15):
     *
     * - B-I6/W1-10: the previous loop set `$covered = true` on the FIRST
     *   matching probe and broke — an existence quantor answering "is ANY
     *   request under this pattern protected?" where the check's own claim
     *   ("jeder Inject-Pfad hat ein Gegenstück") requires a universal
     *   quantor. `neutralising_excludes()` right above already gets this
     *   direction correct for its own probes; this method aligns with it: ALL
     *   probes from `probe_paths()` must be covered.
     * - W1-15: matching only `[rawurldecode($probe), $probe]` covers the
     *   "inject pattern written percent-encoded" direction but not the
     *   reverse ("inject pattern written decoded, guard pattern written
     *   percent-encoded") — `rawurldecode()` on an already-decoded string is
     *   a no-op, so the guard's percent-encoded spelling was never produced
     *   to compare against. Building a third candidate — the probe
     *   percent-re-encoded segment-by-segment (preserving `/`) — covers that
     *   direction too, matching what a real browser sends over the wire for a
     *   non-ASCII path.
     *
     * Public and static — like `Interceptor::match_path()` — so the three
     * fixed constellations (Erst-Treffer, beide Kodierungsrichtungen) can be
     * exercised directly in `tests/test-cli-doctor-checks.php` without
     * bootstrapping the whole WP-CLI command.
     *
     * @param string             $pattern     One `interceptor_inject_paths` pattern (no leading `!`).
     * @param array<int, string> $guard_paths Filtered `interceptor_paths` patterns (see `apply_filters()` call in `__invoke()`).
     */
    public static function inject_pattern_covered( string $pattern, array $guard_paths ): bool {
        foreach ( self::probe_paths( $pattern ) as $probe ) {
            $decoded = rawurldecode( $probe );
            $encoded = implode(
                '/',
                array_map( 'rawurlencode', explode( '/', $decoded ) )
            );

            $probe_covered = false;
            foreach ( array_unique( [ $probe, $decoded, $encoded ] ) as $candidate ) {
                if ( \Creationell\Captcha\Interceptor::match_path( $candidate, $guard_paths ) ) {
                    $probe_covered = true;
                    break;
                }
            }

            if ( ! $probe_covered ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns the `!`-exclusion patterns of a list that on their own match
     * every positive pattern of the same list — i.e. that neutralise it.
     *
     * Probing with concrete sample paths derived from the positive patterns
     * (rather than comparing pattern strings) uses the real matcher, so the
     * answer is exactly the runtime behaviour.
     *
     * B-M23: public (like `inject_pattern_covered()` above) so Check 14's own
     * matching — not just what the check does with the result — has a direct
     * Ebene-2 test in `tests/test-cli-doctor-checks.php`. Before this, the
     * ~300-line doctor addition from Modul 27 had no such coverage at all for the
     * BK-15 exclusion logic; `class-cli-list-command.php:339` makes the identical
     * visibility argument for a comparable validation seam.
     *
     * @param array<int, mixed> $patterns Raw pattern list from the settings.
     * @return array<int, string> Offending `!`-patterns, original spelling.
     */
    public static function neutralising_excludes( array $patterns ): array {
        $positives = [];
        $excludes  = [];

        foreach ( $patterns as $raw ) {
            $pattern = trim( (string) $raw );
            if ( '' === $pattern ) {
                continue;
            }
            if ( str_starts_with( $pattern, '!' ) ) {
                if ( '' !== substr( $pattern, 1 ) ) {
                    $excludes[] = $pattern;
                }
                continue;
            }
            $positives[] = $pattern;
        }

        if ( empty( $positives ) || empty( $excludes ) ) {
            return [];
        }

        $offenders = [];
        foreach ( $excludes as $exclude ) {
            $kills_all = true;
            foreach ( $positives as $positive ) {
                foreach ( self::probe_paths( $positive ) as $probe ) {
                    // match_path() with a single `!`-pattern returns false in
                    // both cases, so test the exclusion as a positive pattern.
                    if ( ! \Creationell\Captcha\Interceptor::match_path( $probe, [ substr( $exclude, 1 ) ] ) ) {
                        $kills_all = false;
                        break 2;
                    }
                }
            }
            if ( $kills_all ) {
                $offenders[] = $exclude;
            }
        }

        return $offenders;
    }

    /**
     * Turns a wildcard pattern into concrete sample strings it covers.
     *
     * Two probes per pattern — `*` expanded to nothing and to a filler — so a
     * narrow exclusion that only catches one of them is not mistaken for one
     * that swallows the whole pattern.
     *
     * B-M23: public for the same reason as `neutralising_excludes()` above.
     *
     * @param string $pattern Wildcard pattern (without a leading `!`).
     * @return array<int, string>
     */
    public static function probe_paths( string $pattern ): array {
        return array_values( array_unique( [
            str_replace( '*', '', $pattern ),
            str_replace( '*', 'creacaptcha-probe', $pattern ),
        ] ) );
    }
}
