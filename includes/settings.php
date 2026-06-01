<?php
/**
 * Settings registration via the WordPress Settings API.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Ordered list of the admin settings tabs.
 *
 * The array key is the tab id; it doubles as the suffix of the Settings-API
 * page slug (`creationell-captcha-tab-<id>`) that do_settings_sections() uses.
 *
 * @return array<string, string> Tab id => visible label.
 */
function creationell_captcha_admin_tabs(): array {
    return [
        'captcha'     => __( 'Captcha', 'creationell-captcha' ),
        'formulare'   => __( 'Formulare', 'creationell-captcha' ),
        'firewall'    => __( 'Firewall', 'creationell-captcha' ),
        'underattack' => __( 'Under-Attack', 'creationell-captcha' ),
        'analytics'   => __( 'Analytics', 'creationell-captcha' ),
        'email'       => __( 'E-Mail-Schutz', 'creationell-captcha' ),
    ];
}

/**
 * Settings sections and the tab each one belongs to.
 *
 * Section order within a tab follows this array's order.
 *
 * @return array<string, array<string, string>> Section id => { tab, title, callback }.
 */
function creationell_captcha_admin_sections(): array {
    return [
        'creationell_captcha_engine'             => [
            'tab'      => 'captcha',
            'title'    => __( 'Proof-of-Work-Engine', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_engine_section',
        ],
        'creationell_captcha_widget_appearance'  => [
            'tab'      => 'captcha',
            'title'    => __( 'Widget-Erscheinungsbild', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_widget_appearance_section',
        ],
        'creationell_captcha_code_challenge'      => [
            'tab'      => 'captcha',
            'title'    => __( 'Bild-Code-Challenge', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_code_challenge_section',
        ],
        'creationell_captcha_core_forms'         => [
            'tab'      => 'formulare',
            'title'    => __( 'WordPress-Kernformulare', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_core_forms_section',
        ],
        'creationell_captcha_interceptor'  => [
            'tab'      => 'formulare',
            'title'    => __( 'Eigene Formular-Pfade (Interceptor)', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_interceptor_section',
        ],
        'creationell_captcha_form_plugins' => [
            'tab'      => 'formulare',
            'title'    => __( 'Formular-Plugins', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_form_plugins_section',
        ],
        'creationell_captcha_proxy'        => [
            'tab'      => 'firewall',
            'title'    => __( 'Proxy & IP-Ermittlung', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_proxy_section',
        ],
        'creationell_captcha_firewall'     => [
            'tab'      => 'firewall',
            'title'    => __( 'IP- & User-Agent-Firewall', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_firewall_section',
        ],
        'creationell_captcha_bypass'       => [
            'tab'      => 'firewall',
            'title'    => __( 'Bypass', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_bypass_section',
        ],
        'creationell_captcha_ratelimit'    => [
            'tab'      => 'firewall',
            'title'    => __( 'Rate-Limiting', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_ratelimit_section',
        ],
        'creationell_captcha_underattack'  => [
            'tab'      => 'underattack',
            'title'    => __( 'Under-Attack-Modus', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_underattack_section',
        ],
        'creationell_captcha_underattack_appearance' => [
            'tab'      => 'underattack',
            'title'    => __( 'Erscheinungsbild', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_underattack_appearance_section',
        ],
        'creationell_captcha_email'        => [
            'tab'      => 'email',
            'title'    => __( 'E-Mail-Obfuskation', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_email_section',
        ],
        'creationell_captcha_analytics'    => [
            'tab'      => 'analytics',
            'title'    => __( 'Event-Logging', 'creationell-captcha' ),
            'callback' => 'creationell_captcha_render_analytics_section',
        ],
    ];
}

/**
 * Field specification for the captcha settings.
 *
 * Every field carries a `section` key naming the section (and thereby the tab)
 * it renders in; the section ids match creationell_captcha_admin_sections().
 *
 * @return array<string, array<string, mixed>>
 */
function creationell_captcha_settings_fields(): array {
    $fields = [
        'algorithm'              => [
            'label'   => __( 'Algorithmus', 'creationell-captcha' ),
            'type'    => 'select',
            'section' => 'creationell_captcha_engine',
            'options' => [
                'pbkdf2'   => 'PBKDF2/SHA-256',
                'argon2id' => 'Argon2id',
            ],
            'help'    => __( 'PBKDF2 ist der ressourcenschonende Default — funktioniert mit jedem PHP-Standard ohne weitere Extensions. Argon2id ist moderner und resistenter gegen GPU-Cracking, erfordert aber die PHP-Extension „sodium". Im Zweifel bei PBKDF2 bleiben.', 'creationell-captcha' ),
        ],
        'difficulty'             => [
            'label'   => __( 'Schwierigkeit', 'creationell-captcha' ),
            'type'    => 'select',
            'section' => 'creationell_captcha_engine',
            'options' => [
                'low'    => __( 'Niedrig', 'creationell-captcha' ),
                'medium' => __( 'Mittel', 'creationell-captcha' ),
                'high'   => __( 'Hoch', 'creationell-captcha' ),
            ],
            'help'    => __( 'Steuert den Rechenaufwand für die Sicherheitsabfrage. „Niedrig" ≈ ~0,1 s auf einem Mittelklasse-Handy, „Mittel" ≈ ~0,3–0,5 s, „Hoch" ≈ ~1–2 s. Höhere Stufen erhöhen den Aufwand für Bot-Farmen, verzögern aber jeden echten Submit. „Mittel" ist der empfohlene Default.', 'creationell-captcha' ),
        ],
        'argon2id_memory'        => [
            'label'   => __( 'Argon2id-Speicher (MiB)', 'creationell-captcha' ),
            'type'    => 'number',
            'section' => 'creationell_captcha_engine',
            'min'     => 8,
            'max'     => 256,
            'help'    => __( 'Nur wirksam, wenn als Algorithmus Argon2id gewählt ist.', 'creationell-captcha' ),
        ],
        'challenge_expiry'       => [
            'label'   => __( 'Challenge-Gültigkeit (Sekunden)', 'creationell-captcha' ),
            'type'    => 'number',
            'section' => 'creationell_captcha_engine',
            'min'     => 60,
            'max'     => 3600,
            'help'    => __( 'Wie lange eine ausgestellte Sicherheitsabfrage gültig bleibt, bevor der Browser eine neue anfordern muss. Kurze Werte (60–120 s) reduzieren Replay-Risiko, können aber bei langsam ausgefüllten Formularen zu „abgelaufen"-Fehlern führen. Default 300 s = 5 Minuten.', 'creationell-captcha' ),
        ],
        'widget_display'         => [
            'label'   => __( 'Anzeige-Modus', 'creationell-captcha' ),
            'type'    => 'select',
            'section' => 'creationell_captcha_widget_appearance',
            'options' => [
                'standard'  => __( 'Standard (sichtbar im Formular)', 'creationell-captcha' ),
                'floating'  => __( 'Schwebend (am Anchor-Element)', 'creationell-captcha' ),
                'overlay'   => __( 'Overlay (Vollbild-Modal)', 'creationell-captcha' ),
                'bar'       => __( 'Bar (am Bildschirmrand)', 'creationell-captcha' ),
                'invisible' => __( 'Unsichtbar (im Hintergrund)', 'creationell-captcha' ),
            ],
            'help'    => __( 'Wie das Widget im Frontend dargestellt wird. „Schwebend" positioniert sich relativ zu einem Anchor (Standard: erster Submit-Button im selben Formular — siehe „Floating-Anchor" unten). Ohne gültigen Anchor bleibt das Widget unsichtbar.', 'creationell-captcha' ),
        ],
        'widget_floating_anchor' => [
            'label'           => __( 'Floating-Anchor', 'creationell-captcha' ),
            'type'            => 'text',
            'section'         => 'creationell_captcha_widget_appearance',
            'help'            => __( 'CSS-Selektor für das Anchor-Element des „Schwebend"-Modus. Beispiele: input[type="submit"], #my-form .submit-row, .wpcf7-submit. Wird das Element nicht gefunden, bleibt das Widget unsichtbar. Leer lassen für den Default: erster Submit-Button im umgebenden Formular.', 'creationell-captcha' ),
            'requires_select' => [ 'widget_display' => 'floating' ],
        ],
        'widget_floating_placement' => [
            'label'           => __( 'Floating-Position', 'creationell-captcha' ),
            'type'            => 'select',
            'section'         => 'creationell_captcha_widget_appearance',
            'options'         => [
                'auto'   => __( 'Automatisch', 'creationell-captcha' ),
                'top'    => __( 'Oberhalb des Anchors', 'creationell-captcha' ),
                'bottom' => __( 'Unterhalb des Anchors', 'creationell-captcha' ),
            ],
            'help'            => __( 'Wo das schwebende Widget relativ zum Anchor erscheint.', 'creationell-captcha' ),
            'requires_select' => [ 'widget_display' => 'floating' ],
        ],
        'widget_floating_offset'    => [
            'label'           => __( 'Floating-Abstand (px)', 'creationell-captcha' ),
            'type'            => 'number',
            'section'         => 'creationell_captcha_widget_appearance',
            'min'             => 0,
            'max'             => 200,
            'help'            => __( 'Vertikaler Abstand zwischen schwebendem Widget und Anchor in Pixeln. ALTCHA-Default: 12.', 'creationell-captcha' ),
            'requires_select' => [ 'widget_display' => 'floating' ],
        ],
        'widget_code_challenge_display' => [
            'label'    => __( 'Code-Challenge-Anzeige', 'creationell-captcha' ),
            'type'     => 'select',
            'section'  => 'creationell_captcha_code_challenge',
            'options'  => [
                'standard'    => __( 'Standard (Inline)', 'creationell-captcha' ),
                'overlay'     => __( 'Overlay (Vollbild-Modal)', 'creationell-captcha' ),
                'bottomsheet' => __( 'Bottom-Sheet (von unten)', 'creationell-captcha' ),
            ],
            'help'     => __( 'Wie die Bild-Code-Eingabe im Widget dargestellt wird, sobald sie als zweite Stufe ausgelöst wurde.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'widget_type'            => [
            'label'   => __( 'Interaktions-Typ', 'creationell-captcha' ),
            'type'    => 'select',
            'section' => 'creationell_captcha_widget_appearance',
            'options' => [
                'checkbox' => __( 'Checkbox (Klassiker)', 'creationell-captcha' ),
                'switch'   => __( 'Switch (Toggle)', 'creationell-captcha' ),
                'native'   => __( 'Native Browser-Checkbox', 'creationell-captcha' ),
            ],
            'help'    => __( 'Optik des Kontrollelements im Widget. „Checkbox" ist der klassische ALTCHA-Look, „Switch" ein Toggle-Schalter, „Native Browser-Checkbox" verwendet das browsereigene Element (passt sich am ehesten dem Theme an).', 'creationell-captcha' ),
        ],
        'widget_auto_trigger'    => [
            'label'   => __( 'Automatische Auslösung', 'creationell-captcha' ),
            'type'    => 'select',
            'section' => 'creationell_captcha_widget_appearance',
            'options' => [
                'none'     => __( 'Keine (Nutzer klickt selbst)', 'creationell-captcha' ),
                'onload'   => __( 'Beim Laden der Seite', 'creationell-captcha' ),
                'onsubmit' => __( 'Beim Abschicken des Formulars', 'creationell-captcha' ),
            ],
            'help'    => __( 'Wann die Sicherheitsabfrage selbsttätig startet. Im unsichtbaren Modus typischerweise „beim Laden" — sonst wirkt das Widget passiv.', 'creationell-captcha' ),
        ],
        'widget_theme'           => [
            'label'   => __( 'Theme', 'creationell-captcha' ),
            'type'    => 'select',
            'section' => 'creationell_captcha_widget_appearance',
            'options' => [
                'default'   => __( 'Standard', 'creationell-captcha' ),
                'aqua'      => __( 'Aqua', 'creationell-captcha' ),
                'business'  => __( 'Business', 'creationell-captcha' ),
                'caramel'   => __( 'Caramel', 'creationell-captcha' ),
                'cupcake'   => __( 'Cupcake', 'creationell-captcha' ),
                'cyberpunk' => __( 'Cyberpunk', 'creationell-captcha' ),
                'lime'      => __( 'Lime', 'creationell-captcha' ),
                'wireframe' => __( 'Wireframe', 'creationell-captcha' ),
            ],
            'help'    => __( 'Vorgefertigtes Farbschema des Widgets. „Standard" ist neutral und passt auf die meisten Themes. Eine Live-Vorschau aller Themes gibt es im ALTCHA-Playground (Link in der Sektionsbeschreibung oben).', 'creationell-captcha' ),
        ],
        'widget_hide_branding'   => [
            'label'   => __( 'ALTCHA-Branding ausblenden', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_widget_appearance',
            'help'    => __( 'Blendet den ALTCHA-Footer und das Logo aus.', 'creationell-captcha' ),
        ],
        'widget_primary_color'   => [
            'label'   => __( 'Akzentfarbe', 'creationell-captcha' ),
            'type'    => 'color',
            'section' => 'creationell_captcha_widget_appearance',
            'help'    => __( 'Überschreibt die Standard-Akzentfarbe des Widgets (Häkchen, Fokusrahmen). Hex-Format, z. B. #0064d1. Leer lassen für den Theme-Default.', 'creationell-captcha' ),
        ],
        'widget_custom_css'      => [
            'label'   => __( 'Eigenes CSS', 'creationell-captcha' ),
            'type'    => 'textblock',
            'section' => 'creationell_captcha_widget_appearance',
            'help'    => __( 'Beliebige CSS-Regeln; werden als Inline-Stylesheet vor dem Widget ausgegeben. Maximal 5 KB. Beispiel: altcha-widget { --altcha-border-radius: 12px; --altcha-color-base: #f7f9fc; } — die kompletten ALTCHA-CSS-Variablen sind unter altcha.org/docs/v2/widget-customization dokumentiert.', 'creationell-captcha' ),
        ],
        'widget_strings_override' => [
            'label'   => __( 'Übersetzungen überschreiben', 'creationell-captcha' ),
            'type'    => 'textblock',
            'section' => 'creationell_captcha_widget_appearance',
            'help'    => __( 'Optionales JSON-Objekt zur Anpassung der Widget-Texte. Beispiel: {"label":"Ich bin Mensch","verifying":"Wird geprüft …","verified":"Verifiziert","error":"Fehler"}. Die vollständige Schlüssel-Liste ist in der ALTCHA-Doku unter altcha.org/docs/v2/website-integration#strings einsehbar. Leer lassen für die automatische Spracherkennung.', 'creationell-captcha' ),
        ],
        'code_challenge_enabled'              => [
            'label'   => __( 'Bild-Code-Challenge aktivieren', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_code_challenge',
            'help'    => __( 'Master-Schalter. Wenn aus, wird nie eine Code-Challenge ausgestellt — unabhängig von den Trigger-Bedingungen unten.', 'creationell-captcha' ),
        ],
        'code_challenge_trigger_always'       => [
            'label'    => __( 'Trigger: Immer (für Tests/erhöhte Sicherheit)', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_code_challenge',
            'help'     => __( 'Jeder Captcha-Request bekommt zusätzlich eine Code-Challenge — unabhängig von Under-Attack, Rate-Limit oder Watch-Liste. Sinnvoll fürs lokale Testen oder pauschal erhöhte Sicherheit. Default aus.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_trigger_underattack'  => [
            'label'    => __( 'Trigger: Under-Attack-Modus', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_code_challenge',
            'help'     => __( 'Wenn der Under-Attack-Modus global aktiv ist, bekommt jeder Captcha-Request zusätzlich eine Code-Challenge.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_trigger_ratelimit'    => [
            'label'    => __( 'Trigger: Rate-Limit-Schwelle erreicht', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_code_challenge',
            'help'     => __( 'Wenn der Rate-Limit-Zähler dieser IP über den unten gewählten Prozentsatz steigt, wird zusätzlich eine Code-Challenge ausgestellt. Setzt voraus, dass das Rate-Limiting unter „Firewall → Rate-Limiting" eingeschaltet ist — sonst hat dieser Trigger keine Wirkung.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_ratelimit_threshold'  => [
            'label'    => __( 'Rate-Limit-Schwellwert (%)', 'creationell-captcha' ),
            'type'     => 'number',
            'section'  => 'creationell_captcha_code_challenge',
            'min'      => 50,
            'max'      => 95,
            'help'     => __( 'Ab welchem Prozentsatz des konfigurierten Rate-Limits die Code-Challenge ausgespielt wird. Default 75 %.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_trigger_watchlist'    => [
            'label'    => __( 'Trigger: IP in Watch-Liste', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_code_challenge',
            'help'     => __( 'IPs auf der Watch-Liste (unten) werden NICHT blockiert — sie bekommen zusätzlich zur PoW eine Bild-Code-Eingabe.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_watchlist'            => [
            'label'    => __( 'Watch-Liste (IPs/CIDRs)', 'creationell-captcha' ),
            'type'     => 'textarea',
            'section'  => 'creationell_captcha_code_challenge',
            'help'     => __( 'Eine IP-Adresse oder ein CIDR-Bereich je Zeile, z. B. 203.0.113.4 oder 2a06:98c0::/29. Diese IPs werden NICHT blockiert — sie bekommen zusätzlich zur PoW eine Bild-Code-Eingabe. Für komplette Sperrung: IP-Blockliste unter Firewall.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_length'               => [
            'label'    => __( 'Code-Länge (Zeichen)', 'creationell-captcha' ),
            'type'     => 'number',
            'section'  => 'creationell_captcha_code_challenge',
            'min'      => 4,
            'max'      => 8,
            'help'     => __( 'Anzahl der Zeichen im Bild-Code. Default 5.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_charset'              => [
            'label'    => __( 'Code-Zeichensatz', 'creationell-captcha' ),
            'type'     => 'select',
            'section'  => 'creationell_captcha_code_challenge',
            'options'  => [
                'digits'                    => __( 'Nur Ziffern (0–9)', 'creationell-captcha' ),
                'alphanumeric'              => __( 'Buchstaben + Ziffern (A–Z, 0–9)', 'creationell-captcha' ),
                'alphanumeric-no-confusing' => __( 'Buchstaben + Ziffern ohne Verwechsler (Default)', 'creationell-captcha' ),
            ],
            'help'     => __( 'Der „ohne Verwechsler"-Charset entfernt 0/O/1/I/l für bessere Lesbarkeit.', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'code_challenge_expiry'               => [
            'label'    => __( 'Token-Gültigkeit (Sekunden)', 'creationell-captcha' ),
            'type'     => 'number',
            'section'  => 'creationell_captcha_code_challenge',
            'min'      => 60,
            'max'      => 900,
            'help'     => __( 'Wie lange ein ausgestellter Code-Challenge-Token gültig bleibt. Kurz halten reduziert Replay-Risiko. Default 300 s (5 min).', 'creationell-captcha' ),
            'requires' => 'code_challenge_enabled',
        ],
        'protect_comments'       => [
            'label'   => __( 'Kommentarformular schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_core_forms',
        ],
        'protect_login'          => [
            'label'   => __( 'Login-Formular schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_core_forms',
        ],
        'protect_registration'   => [
            'label'   => __( 'Registrierung schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_core_forms',
            'help'    => __( 'Schützt das Standard-Registrierungsformular (wp-login.php?action=register). Wirkt unabhängig vom „Mitgliedschaft"-Toggle in den allgemeinen WordPress-Einstellungen.', 'creationell-captcha' ),
        ],
        'protect_password_reset' => [
            'label'   => __( 'Passwort-Reset schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_core_forms',
            'help'    => __( 'Schützt /wp-login.php?action=lostpassword. Bei aktivem WooCommerce wird auch die Woo-„Passwort vergessen"-Seite mit abgedeckt — die WooCommerce-Lost-Password-Option ist nur für das Widget-Rendering zuständig, die Server-Verifikation läuft hier.', 'creationell-captcha' ),
        ],
        'skip_logged_in'         => [
            'label'   => __( 'Kommentar-Captcha für angemeldete Nutzer überspringen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_core_forms',
            'help'    => __( 'Wirkt ausschließlich für das Kommentarformular — die Login-, Registrierungs- und Passwort-Reset-Formulare sind für angemeldete Nutzer ohnehin nicht relevant.', 'creationell-captcha' ),
        ],
        'interceptor_enabled'        => [
            'label'   => __( 'Interceptor aktivieren', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_interceptor',
            'help'    => __( 'Generischer serverseitiger Schutz für eigene Formular-Pfade. Ohne eingetragene Pfade, Aktionen oder Inject-Pfade ohne Wirkung.', 'creationell-captcha' ),
        ],
        'interceptor_paths'          => [
            'label'    => __( 'Geschützte Pfade', 'creationell-captcha' ),
            'type'     => 'textarea',
            'section'  => 'creationell_captcha_interceptor',
            'help'     => __( 'Ein URL-Pfad-Muster je Zeile, z. B. /kontakt-senden oder /custom/*. Der Stern „*" ist ein Platzhalter. POST-Anfragen auf passende Pfade müssen eine gelöste Sicherheitsabfrage mitführen. Bei Installationen in einem Unterverzeichnis das Verzeichnis im Muster mitangeben. Beginnt eine Zeile mit „!", ist sie ein Ausschluss-Muster (Allow-Liste-Ausnahme).', 'creationell-captcha' ),
            'requires' => 'interceptor_enabled',
        ],
        'interceptor_actions'        => [
            'label'    => __( 'Geschützte Aktionen', 'creationell-captcha' ),
            'type'     => 'textarea',
            'section'  => 'creationell_captcha_interceptor',
            'help'     => __( 'Ein Wildcard-Muster je Zeile für WordPress-Action-Namen (z. B. my_form_submit, my_form_*). Anfragen mit passendem $_POST[action] oder $_GET[action] müssen eine gelöste Sicherheitsabfrage mitführen — auch in wp-admin/admin-post.php oder admin-ajax.php. Erlaubte Zeichen: a–z, 0–9, „_", „-", „*". Beginnt eine Zeile mit „!", ist sie ein Ausschluss-Muster. Angemeldete Nutzer mit Rechten ab edit_posts (Autoren/Editoren/Admins) sind weiterhin ausgenommen — der Schutz wirkt nur gegen anonyme bzw. Subscriber-Anfragen.', 'creationell-captcha' ),
            'requires' => 'interceptor_enabled',
        ],
        'interceptor_inject_paths'   => [
            'label'    => __( 'Inject-Pfade', 'creationell-captcha' ),
            'type'     => 'textarea',
            'section'  => 'creationell_captcha_interceptor',
            'help'     => __( 'Ein URL-Pfad-Muster je Zeile. Auf passenden Seiten wird die Sicherheitsabfrage automatisch vor jedem „</form>" injiziert — nützlich für Theme- oder Drittanbieter-Formulare, die sich nicht direkt modifizieren lassen. „*" als Platzhalter; Zeilen mit „!" als Ausschluss.', 'creationell-captcha' ),
            'requires' => 'interceptor_enabled',
        ],
        'interceptor_skip_logged_in' => [
            'label'    => __( 'Interceptor für angemeldete Nutzer überspringen', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_interceptor',
            'help'     => __( 'Wenn aktiv, läuft der Interceptor für alle angemeldeten Nutzer (egal welcher Rolle) leer — die Sicherheitsabfrage wird im Inject-Pfade-Modus weiterhin angezeigt, aber nicht serverseitig erzwungen. Nützlich für Member-Bereiche, in denen POSTs nicht bot-anfällig sind.', 'creationell-captcha' ),
            'requires' => 'interceptor_enabled',
        ],
    ];

    if ( class_exists( 'WPCF7_ContactForm' ) ) {
        $fields['protect_cf7'] = [
            'label'   => __( 'Contact Form 7 schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_form_plugins',
            'help'    => __( 'Schützt alle CF7-Formulare per Auto-Inject vor dem Submit-Button. Position manuell steuern: den Form-Tag [creationell_captcha] an die gewünschte Stelle des CF7-Formulars setzen.', 'creationell-captcha' ),
        ];
    }

    if ( class_exists( 'Forminator' ) ) {
        $fields['protect_forminator'] = [
            'label'   => __( 'Forminator schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_form_plugins',
            'help'    => __( 'Schützt alle Forminator-Custom-Forms per Auto-Inject vor dem Submit-Button. Polls und Quizzes sind ausgenommen.', 'creationell-captcha' ),
        ];
    }

    if ( class_exists( 'WPForms' ) ) {
        $fields['protect_wpforms'] = [
            'label'   => __( 'WPForms schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_form_plugins',
            'help'    => __( 'Schützt alle WPForms-Formulare per Auto-Inject vor dem Submit-Button.', 'creationell-captcha' ),
        ];
    }

    if ( class_exists( 'WooCommerce' ) ) {
        $fields['protect_woocommerce'] = [
            'label'   => __( 'WooCommerce schützen', 'creationell-captcha' ),
            'type'    => 'checkbox',
            'section' => 'creationell_captcha_form_plugins',
            'help'    => __( 'Schützt Checkout, My-Account-Login, Registrierung und Lost-Password. Produkt-Bewertungen sind durch „Kommentare schützen" abgedeckt.', 'creationell-captcha' ),
        ];
        $fields['protect_wc_checkout'] = [
            'label'    => __( 'Checkout schützen', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_form_plugins',
            'requires' => 'protect_woocommerce',
        ];
        $fields['protect_wc_login'] = [
            'label'    => __( 'My-Account-Login schützen', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_form_plugins',
            'requires' => 'protect_woocommerce',
        ];
        $fields['protect_wc_registration'] = [
            'label'    => __( 'My-Account-Registrierung schützen', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_form_plugins',
            'requires' => 'protect_woocommerce',
        ];
        $fields['protect_wc_lost_password'] = [
            'label'    => __( 'Lost-Password schützen', 'creationell-captcha' ),
            'type'     => 'checkbox',
            'section'  => 'creationell_captcha_form_plugins',
            'requires' => 'protect_woocommerce',
            'help'     => __( 'Zeigt das Widget auf der Woo-Lost-Password-Seite. Die serverseitige Verifikation läuft über „Passwort-Reset schützen" (WP-Kernformular); aktivieren Sie diese Option, falls noch nicht geschehen.', 'creationell-captcha' ),
        ];
    }

    $fields['firewall_enabled'] = [
        'label'   => __( 'Firewall aktivieren', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_firewall',
        'help'    => __( 'IP- und User-Agent-Blockierung. Ohne eingetragene Listen ohne Wirkung.', 'creationell-captcha' ),
    ];
    $fields['firewall_behind_proxy'] = [
        'label'   => __( 'Site läuft hinter einem Reverse-Proxy/CDN', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_proxy',
        'help'    => __( 'Nur aktivieren, wenn die Site tatsächlich hinter einem Proxy/CDN läuft — sonst lässt sich die Client-IP fälschen.', 'creationell-captcha' ),
    ];
    $fields['firewall_proxy_header'] = [
        'label'   => __( 'Proxy-Header für die Client-IP', 'creationell-captcha' ),
        'type'    => 'select',
        'section' => 'creationell_captcha_proxy',
        'options' => [
            'x-forwarded-for'  => 'X-Forwarded-For',
            'x-real-ip'        => 'X-Real-IP',
            'cf-connecting-ip' => 'CF-Connecting-IP',
            'true-client-ip'   => 'True-Client-IP',
        ],
        'help'    => __( 'Welcher Header die echte Client-IP trägt. „X-Forwarded-For" ist Standard bei nginx, Apache mod_remoteip und den meisten CDNs. „CF-Connecting-IP" verwendet Cloudflare nativ. „X-Real-IP" / „True-Client-IP" sind seltener, kommen aber bei Akamai bzw. einigen nginx-Setups vor. Nur wirksam, wenn der Proxy-Modus aktiv ist.', 'creationell-captcha' ),
        'requires' => 'firewall_behind_proxy',
    ];
    $fields['firewall_ip_block'] = [
        'label'   => __( 'IP-Blockliste', 'creationell-captcha' ),
        'type'    => 'textarea',
        'section' => 'creationell_captcha_firewall',
        'help'    => __( 'Eine IP-Adresse oder ein CIDR-Bereich je Zeile, z. B. 203.0.113.4, 203.0.113.0/24 oder 2a06:98c0::/29. Anfragen von diesen Adressen werden mit HTTP 403 abgewiesen — bevor sie WordPress laden. Maximal 50 Einträge.', 'creationell-captcha' ),
    ];
    $fields['firewall_ip_allow'] = [
        'label'   => __( 'IP-Erlaubnisliste (global)', 'creationell-captcha' ),
        'type'    => 'textarea',
        'section' => 'creationell_captcha_bypass',
        'help'    => __( 'Eine IP-Adresse oder ein CIDR-Bereich (z. B. 203.0.113.0/24, 2a06:98c0::/29) je Zeile. Diese IPs werden von der Firewall, vom Rate-Limiter, vom Captcha und vom Under-Attack-Modus durchgewinkt.', 'creationell-captcha' ),
    ];
    $fields['bypass_ua_allow'] = [
        'label'   => __( 'User-Agent-Bypass', 'creationell-captcha' ),
        'type'    => 'textarea',
        'section' => 'creationell_captcha_bypass',
        'help'    => __( 'Eine Wildcard pro Zeile, „*" als Platzhalter (z. B. *pingdom*, *StatusCake*). Anfragen mit passendem User-Agent werden vom gesamten Schutz ausgenommen.', 'creationell-captcha' ),
    ];
    $fields['bypass_cookies'] = [
        'label'   => __( 'Cookie-Bypass', 'creationell-captcha' ),
        'type'    => 'textarea',
        'section' => 'creationell_captcha_bypass',
        'help'    => __( 'Eine Zeile pro Eintrag im Format „cookie_name=wert" (exakter Wert-Match). Anfragen mit passendem Cookie werden vom gesamten Schutz ausgenommen — typischer Anwendungsfall: ein internes Monitoring-Tool setzt einen Cookie monitoring_token=<sehr-langer-zufallswert> und kann damit die Site überwachen, ohne von der Firewall blockiert zu werden. „name" muss alphanumerisch sein (zusätzlich „_" und „-"); der Wert darf bis 200 Zeichen lang sein.', 'creationell-captcha' ),
    ];
    $fields['firewall_ua_block'] = [
        'label'   => __( 'User-Agent-Blockliste', 'creationell-captcha' ),
        'type'    => 'textarea',
        'section' => 'creationell_captcha_firewall',
        'help'    => __( 'Ein Wildcard-Muster je Zeile, „*" als Platzhalter (Groß-/Kleinschreibung egal). Beispiele: *badbot*, MJ12bot/*, *python-requests/*. Anfragen mit passendem User-Agent werden mit HTTP 403 abgewiesen. Hinweis: Ausschluss-Muster mit „!"-Präfix werden hier NICHT unterstützt — Ausnahmen unter „User-Agent-Bypass" (Sektion Bypass) eintragen.', 'creationell-captcha' ),
    ];
    $fields['firewall_trusted_proxies'] = [
        'label'   => __( 'Vertrauenswürdige Proxies', 'creationell-captcha' ),
        'type'    => 'textarea',
        'section' => 'creationell_captcha_proxy',
        'help'    => __( 'Eine IP-Adresse oder ein CIDR-Bereich (z. B. 203.0.113.0/24, 2a06:98c0::/29) je Zeile. Nur Anfragen, die von einer dieser IPs kommen, dürfen den weitergeleiteten Header setzen.', 'creationell-captcha' ),
        'requires' => 'firewall_behind_proxy',
    ];
    $fields['firewall_trust_private_ranges'] = [
        'label'   => __( 'Private/Loopback-Netze vertrauen', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_proxy',
        'help'    => __( 'Vertraut 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1/128 und fc00::/7. Bequem für Setups hinter NAT; in mehrmandantigen Hosting-Umgebungen (Shared Hosting) mit Vorsicht aktivieren.', 'creationell-captcha' ),
        'requires' => 'firewall_behind_proxy',
    ];
    $fields['firewall_trust_cloudflare'] = [
        'label'   => __( 'Cloudflare-Netze vertrauen', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_proxy',
        'help'    => __( 'Vertraut den von Cloudflare veröffentlichten IPv4-/IPv6-Ranges. Ein Snapshot wird mit dem Plugin ausgeliefert.', 'creationell-captcha' ),
        'requires' => 'firewall_behind_proxy',
    ];
    $fields['firewall_cloudflare_auto_refresh'] = [
        'label'   => __( 'CF-Ranges automatisch aktualisieren', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_proxy',
        'help'    => __( 'Aktualisiert die Cloudflare-Range-Liste täglich über WP-Cron von cloudflare.com. Setzt einen funktionierenden Cron voraus — bei Sites mit DISABLE_WP_CRON=true sicherstellen, dass ein System-Cron wp-cron.php aufruft. Status (letzter Lauf, nächste Ausführung) sichtbar unter „CreaCaptcha → Werkzeuge → Cloudflare-IP-Cache".', 'creationell-captcha' ),
        'requires' => 'firewall_trust_cloudflare',
    ];
    $fields['ratelimit_enabled'] = [
        'label'   => __( 'Rate-Limiting aktivieren', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_ratelimit',
        'help'    => __( 'Begrenzt die Anzahl der POST-Anfragen pro IP-Adresse innerhalb eines Zeitfensters. Wenn das Limit überschritten wird, antwortet der Server mit HTTP 429 (Too Many Requests).', 'creationell-captcha' ),
    ];
    $fields['ratelimit_scope'] = [
        'label'   => __( 'Rate-Limit-Bereich', 'creationell-captcha' ),
        'type'    => 'select',
        'section' => 'creationell_captcha_ratelimit',
        'options' => [
            'core'  => __( 'Login & WP-Kernformulare', 'creationell-captcha' ),
            'forms' => __( 'Zusätzlich CF7- & Forminator-Formulare (Whitelist)', 'creationell-captcha' ),
            'all'   => __( 'Alle Front-End-Anfragen', 'creationell-captcha' ),
        ],
        'help'    => __( 'Wofür der Rate-Limiter zählt. „Login & WP-Kernformulare" — sehr eng, Default-Wert 30/300 passt. „Zusätzlich CF7- & Forminator-Formulare" — etwas größer wählen (z. B. 60/300). „Alle Front-End-Anfragen" — bei jedem Seitenaufruf wird gezählt; Wert deutlich höher setzen (z. B. 300/300), ein persistenter Object-Cache wird empfohlen.', 'creationell-captcha' ),
    ];
    $fields['ratelimit_max'] = [
        'label'   => __( 'Max. Anfragen pro Fenster', 'creationell-captcha' ),
        'type'    => 'number',
        'section' => 'creationell_captcha_ratelimit',
        'min'     => 1,
        'max'     => 10000,
        'help'    => __( 'Maximalzahl an POST-Anfragen pro IP-Adresse je Zeitfenster, bevor blockiert wird. Defaults (30 Anfragen / 300 Sekunden = 5 Minuten) sind eine vorsichtige Grundeinstellung für Login/Comments. Für Scope „Alle Front-End-Anfragen" deutlich höher setzen (z. B. 300/300).', 'creationell-captcha' ),
    ];
    $fields['ratelimit_window'] = [
        'label'   => __( 'Zeitfenster (Sekunden)', 'creationell-captcha' ),
        'type'    => 'number',
        'section' => 'creationell_captcha_ratelimit',
        'min'     => 10,
        'max'     => 3600,
        'help'    => __( 'Dauer des Zähl-Fensters in Sekunden. Ein neuer Bucket beginnt jeweils zur vollen Minute/Stunde; ein 300-Sekunden-Fenster entspricht 5 Minuten. Werte zwischen 60 und 900 sind üblich.', 'creationell-captcha' ),
    ];

    $fields['underattack_enabled'] = [
        'label'   => __( 'Under-Attack-Modus aktivieren', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_underattack',
        'help'    => __( 'Notfall-Modus: Jeder anonyme Besucher der Frontend-Seiten muss erst eine Sicherheitsabfrage bestehen, bevor er HTML bekommt. WP-Admin, REST-API und Cron-Jobs sind inherent ausgenommen (wirken weiter normal). Ein aktiver Full-Page-Cache muss währenddessen deaktiviert/umgangen werden, sonst wird der Modus für gecachte Seiten umgangen. Angemeldete Nutzer aller Rollen sehen das Interstitial nicht.', 'creationell-captcha' ),
    ];
    $fields['underattack_pass_duration'] = [
        'label'   => __( 'Pass-Dauer (Sekunden)', 'creationell-captcha' ),
        'type'    => 'number',
        'section' => 'creationell_captcha_underattack',
        'min'     => 300,
        'max'     => 86400,
        'help'    => __( 'Wie lange ein Besucher nach bestandener Abfrage frei surfen darf, bevor er erneut geprüft wird.', 'creationell-captcha' ),
    ];

    $fields['underattack_logo_url'] = [
        'label'    => __( 'Logo-URL', 'creationell-captcha' ),
        'type'     => 'text',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'URL zu einer Bilddatei (z. B. aus der Mediathek kopiert). Wird zentriert über der Überschrift angezeigt. Leer lassen = kein Logo. Die Höhe ist auf 128 px gedeckelt; für Feinjustierung das Feld „Eigenes CSS" mit dem Selektor .crea-ua-logo verwenden.', 'creationell-captcha' ),
    ];
    $fields['underattack_text_title'] = [
        'label'    => __( 'Browser-Tab-Titel', 'creationell-captcha' ),
        'type'     => 'text',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'Wird als <title>-Tag der Interstitial-Seite ausgegeben. Leer lassen für den Default „Sicherheitsprüfung".', 'creationell-captcha' ),
    ];
    $fields['underattack_text_heading'] = [
        'label'    => __( 'Überschrift', 'creationell-captcha' ),
        'type'     => 'text',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'Große Überschrift mittig auf der Seite. Leer lassen für den Default „Die Website wird gerade besonders geschützt".', 'creationell-captcha' ),
    ];
    $fields['underattack_text_message'] = [
        'label'    => __( 'Hinweistext', 'creationell-captcha' ),
        'type'     => 'textblock',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'Erläuternder Text unter der Überschrift. Leer lassen für den Default „Ihr Browser wird kurz geprüft — einen Moment bitte.".', 'creationell-captcha' ),
    ];
    $fields['underattack_text_noscript'] = [
        'label'    => __( 'NoScript-Hinweis', 'creationell-captcha' ),
        'type'     => 'text',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'Wird nur angezeigt, wenn der Browser JavaScript deaktiviert hat. Leer lassen für den Default „Für die Sicherheitsprüfung muss JavaScript aktiviert sein.".', 'creationell-captcha' ),
    ];
    $fields['underattack_color_background'] = [
        'label'    => __( 'Hintergrundfarbe', 'creationell-captcha' ),
        'type'     => 'color',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'Hex-Format, z. B. #0a0a0a. Leer lassen für den Default #f0f0f1.', 'creationell-captcha' ),
    ];
    $fields['underattack_color_text'] = [
        'label'    => __( 'Textfarbe', 'creationell-captcha' ),
        'type'     => 'color',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'Hex-Format, z. B. #ffffff. Leer lassen für den Default #1d2327.', 'creationell-captcha' ),
    ];
    $fields['underattack_custom_css'] = [
        'label'    => __( 'Eigenes CSS', 'creationell-captcha' ),
        'type'     => 'textblock',
        'section'  => 'creationell_captcha_underattack_appearance',
        'requires' => 'underattack_enabled',
        'help'     => __( 'Beliebige CSS-Regeln. Werden im <head> nach dem Default-Stylesheet ausgegeben und überschreiben dort alles. Beispielselektoren: body { ... }, .crea-ua { ... }, .crea-ua h1 { ... }, .crea-ua p { ... }. CSS-Variablen: --creationell-captcha-ua-bg, --creationell-captcha-ua-text.', 'creationell-captcha' ),
    ];

    $fields['analytics_event_log'] = [
        'label'   => __( 'Detaillierten Event-Log aktivieren', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_analytics',
        'help'    => __( 'Schreibt zusätzlich zu den aggregierten Zählern jedes Ereignis mit Zeitstempel, IP, Pfad und Kontextdaten in eine eigene Datenbanktabelle. IP-Adressen sind personenbezogene Daten — bitte den Datenschutzhinweis der Website entsprechend ergänzen oder die „IP-Adressen anonymisieren"-Option unten aktiv lassen (Default). Die Tabelle wächst mit dem Traffic; die aggregierte Zählung bleibt davon unabhängig klein.', 'creationell-captcha' ),
    ];
    $fields['analytics_log_retention'] = [
        'label'   => __( 'Event-Log-Aufbewahrung (Tage)', 'creationell-captcha' ),
        'type'    => 'number',
        'section' => 'creationell_captcha_analytics',
        'min'     => 1,
        'max'     => 365,
        'help'    => __( 'Ältere Einträge im Event-Log werden automatisch entfernt. Nur wirksam, wenn der Event-Log aktiv ist.', 'creationell-captcha' ),
    ];
    $fields['log_verified'] = [
        'label'    => __( 'Erfolgreiche Verifikationen loggen', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Schreibt erfolgreich verifizierte Captcha-Lösungen in den Detail-Log.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['log_failed'] = [
        'label'    => __( 'Fehlgeschlagene Verifikationen loggen', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Schreibt fehlgeschlagene Captcha-Lösungen in den Detail-Log.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['log_firewall'] = [
        'label'    => __( 'Firewall-Blocks loggen', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Schreibt Firewall-Treffer in den Detail-Log.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['log_ratelimit'] = [
        'label'    => __( 'Rate-Limit-Blocks loggen', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Schreibt Rate-Limit-Überschreitungen in den Detail-Log.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['log_underattack'] = [
        'label'    => __( 'Under-Attack-Abfragen loggen', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Schreibt jede ausgelieferte Under-Attack-Sicherheitsabfrage in den Detail-Log.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['log_underattack_passed'] = [
        'label'    => __( 'Bestandene Under-Attack-Prüfungen loggen', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Schreibt jede bestandene Under-Attack-Sicherheitsabfrage in den Detail-Log.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['log_challenge'] = [
        'label'    => __( 'Ausgestellte Challenges loggen', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Schreibt jeden REST-Aufruf der Challenge-Route in den Detail-Log. Hochvolumig — nur aktivieren, wenn explizit gebraucht. Aggregierte Tages- und Stundenzähler erfassen Challenges unabhängig von dieser Einstellung.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['log_body'] = [
        'label'    => __( 'Request-Body-Fingerabdruck speichern', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Speichert pro Event-Log-Zeile eine JSON-Map aus Feldnamen und Wertlängen — ohne die Werte selbst. Hilft bei der Analyse von Angriffsmustern.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];
    $fields['analytics_anonymize_ip'] = [
        'label'    => __( 'IP-Adressen anonymisieren', 'creationell-captcha' ),
        'type'     => 'checkbox',
        'section'  => 'creationell_captcha_analytics',
        'help'     => __( 'Setzt bei IPv4-Adressen das letzte Oktett auf 0 (es bleiben die ersten drei erhalten) und nullt bei IPv6-Adressen die letzten 80 Bit (die ersten 48 bleiben erhalten), bevor sie in den Event-Log geschrieben werden. DSGVO-konform.', 'creationell-captcha' ),
        'requires' => 'analytics_event_log',
    ];

    $fields['obfuscate_emails'] = [
        'label'   => __( 'E-Mail-Obfuskation aktivieren', 'creationell-captcha' ),
        'type'    => 'checkbox',
        'section' => 'creationell_captcha_email',
        'help'    => __( 'Verschleiert mailto-Links und E-Mail-Adressen in Beitragsinhalten, Auszügen, Text-Widgets und Kommentaren, sodass Spam-Bots sie nicht auslesen können. Ohne JavaScript erscheint statt der Adresse ein Platzhalter.', 'creationell-captcha' ),
    ];
    $fields['obfuscate_emails_mode'] = [
        'label'   => __( 'Verarbeitungs-Modus', 'creationell-captcha' ),
        'type'    => 'select',
        'section' => 'creationell_captcha_email',
        'options' => [
            'content' => __( 'Content-Filter (Beiträge, Auszüge, Widgets, Kommentare)', 'creationell-captcha' ),
            'buffer'  => __( 'Ganzseiten-Buffer (gesamte Seite, auch Theme-Templates)', 'creationell-captcha' ),
        ],
        'help'    => __( 'Content-Filter ist leichtgewichtig und sicher — er sieht nur Beitragsinhalte, Auszüge, Widget-Texte und Kommentare. Der Ganzseiten-Buffer erfasst zusätzlich theme-hart-kodierte Adressen (z. B. im Footer/Header), verarbeitet dafür das gesamte Seiten-HTML je Aufruf (CPU-Aufwand bei jedem Pageview; ggf. mit Full-Page-Cache kombinieren). Nur wirksam, wenn die E-Mail-Obfuskation oben aktiv ist.', 'creationell-captcha' ),
    ];

    return $fields;
}

/**
 * Registers the plugin setting, the per-tab sections and the fields.
 */
function creationell_captcha_register_settings(): void {
    register_setting(
        'creationell_captcha',
        'creationell_captcha_settings',
        [
            'type'              => 'array',
            'sanitize_callback' => 'creationell_captcha_sanitize_settings',
            'default'           => creationell_captcha_get_default_settings(),
        ]
    );

    $sections = creationell_captcha_admin_sections();

    // Each section is registered against its tab's page slug; do_settings_sections()
    // is page-scoped, so the render function can emit one tab panel per slug.
    foreach ( $sections as $section_id => $section ) {
        add_settings_section(
            $section_id,
            $section['title'],
            $section['callback'],
            'creationell-captcha-tab-' . $section['tab']
        );
    }

    foreach ( creationell_captcha_settings_fields() as $key => $field ) {
        $section_id = (string) ( $field['section'] ?? '' );

        // Skip a field whose section is unknown — defensive, should not happen.
        if ( ! isset( $sections[ $section_id ] ) ) {
            continue;
        }

        add_settings_field(
            'creationell_captcha_' . $key,
            $field['label'],
            'creationell_captcha_render_field',
            'creationell-captcha-tab-' . $sections[ $section_id ]['tab'],
            $section_id,
            [ 'key' => $key ] + $field
        );
    }
}
add_action( 'admin_init', 'creationell_captcha_register_settings' );

/**
 * Sanitises the settings array before it is stored.
 *
 * @param mixed $input Raw input from the settings form.
 * @return array<string, mixed>
 */
function creationell_captcha_sanitize_settings( mixed $input ): array {
    $defaults = creationell_captcha_get_default_settings();

    if ( ! is_array( $input ) ) {
        return $defaults;
    }

    $clean = [];
    foreach ( creationell_captcha_settings_fields() as $key => $field ) {
        // Invariant: every key returned by creationell_captcha_settings_fields()
        // must have a matching default in creationell_captcha_get_default_settings().
        $default = $defaults[ $key ];

        switch ( $field['type'] ) {
            case 'select':
                $value         = isset( $input[ $key ] ) ? (string) $input[ $key ] : (string) $default;
                $clean[ $key ] = array_key_exists( $value, $field['options'] ) ? $value : $default;
                break;

            case 'number':
                $value         = isset( $input[ $key ] ) ? (int) $input[ $key ] : (int) $default;
                $clean[ $key ] = max( (int) $field['min'], min( (int) $field['max'], $value ) );
                break;

            case 'checkbox':
                $clean[ $key ] = ! empty( $input[ $key ] );
                break;

            case 'color':
                $raw = isset( $input[ $key ] ) ? trim( (string) $input[ $key ] ) : '';
                if ( '' === $raw ) {
                    $clean[ $key ] = '';
                    break;
                }
                $sanitized     = sanitize_hex_color( $raw );
                $clean[ $key ] = ( null === $sanitized ) ? (string) $default : $sanitized;
                break;

            case 'text':
                $raw           = isset( $input[ $key ] ) ? (string) $input[ $key ] : '';
                $clean[ $key ] = substr( sanitize_text_field( $raw ), 0, 255 );
                break;

            case 'textblock':
                $raw           = isset( $input[ $key ] ) ? (string) $input[ $key ] : '';
                $trimmed       = trim( $raw );
                $clean[ $key ] = ( strlen( $trimmed ) > 5120 ) ? substr( $trimmed, 0, 5120 ) : $trimmed;
                break;

            case 'textarea':
                // Das Settings-Formular liefert eine zeilengetrennte Zeichenkette;
                // programmatische Aufrufer (Import, WP-CLI) liefern bereits ein Array.
                if ( isset( $input[ $key ] ) && is_array( $input[ $key ] ) ) {
                    $lines = $input[ $key ];
                } else {
                    $raw   = isset( $input[ $key ] ) ? (string) $input[ $key ] : '';
                    $lines = preg_split( '/\r\n|\r|\n/', $raw ) ?: [];
                }
                $clean_lines = [];
                foreach ( $lines as $line ) {
                    $line = sanitize_text_field( trim( (string) $line ) );
                    if ( '' === $line || strlen( $line ) > 255 ) {
                        continue;
                    }
                    $clean_lines[] = $line;
                    if ( count( $clean_lines ) >= 50 ) {
                        break;
                    }
                }
                $clean[ $key ] = $clean_lines;
                break;
        }
    }

    // widget_custom_css: strip any embedded HTML tags (defence in depth — the
    // value is only ever echoed inside <style>, but a stray </style> would
    // break out). wp_strip_all_tags() removes tags and trims whitespace.
    if ( isset( $clean['widget_custom_css'] ) ) {
        $clean['widget_custom_css'] = wp_strip_all_tags( (string) $clean['widget_custom_css'] );
    }

    // underattack_custom_css: same XSS hardening as widget_custom_css — embedded
    // </style><script>… injection is neutralised here before the value ever
    // reaches the interstitial template.
    if ( isset( $clean['underattack_custom_css'] ) ) {
        $clean['underattack_custom_css'] = wp_strip_all_tags( (string) $clean['underattack_custom_css'] );
    }

    // underattack_logo_url: harden to a clean URL. esc_url_raw() strips dangerous
    // schemes (javascript: etc.) and invalid characters; empty stays empty.
    if ( isset( $clean['underattack_logo_url'] ) ) {
        $raw = trim( (string) $clean['underattack_logo_url'] );
        $clean['underattack_logo_url'] = ( '' === $raw ) ? '' : esc_url_raw( $raw );
    }

    // widget_strings_override: must be valid JSON (or empty). Re-encode after
    // parsing to normalise formatting. Invalid JSON is dropped with an admin
    // notice.
    if ( isset( $clean['widget_strings_override'] ) && '' !== $clean['widget_strings_override'] ) {
        $parsed = json_decode( (string) $clean['widget_strings_override'], true );
        if ( ! is_array( $parsed ) ) {
            $clean['widget_strings_override'] = '';
            add_settings_error(
                'creationell_captcha_settings',
                'widget_strings_invalid',
                __( '„Übersetzungen überschreiben" enthielt ungültiges JSON und wurde verworfen.', 'creationell-captcha' ),
                'warning'
            );
        } else {
            $encoded = wp_json_encode( $parsed );
            $clean['widget_strings_override'] = is_string( $encoded ) ? $encoded : '';
        }
    }

    // firewall_ip_allow: drop entries that are not valid IPs or CIDR ranges.
    if ( isset( $clean['firewall_ip_allow'] ) && is_array( $clean['firewall_ip_allow'] ) ) {
        $valid_lines   = [];
        $invalid_count = 0;
        foreach ( $clean['firewall_ip_allow'] as $line ) {
            if ( creationell_captcha_is_valid_ip_or_cidr( (string) $line ) ) {
                $valid_lines[] = (string) $line;
            } else {
                ++$invalid_count;
            }
        }
        $clean['firewall_ip_allow'] = $valid_lines;
        if ( $invalid_count > 0 ) {
            add_settings_error(
                'creationell_captcha_settings',
                'ip_allow_invalid',
                sprintf(
                    /* translators: %d is the number of dropped entries. */
                    _n(
                        '%d ungültige Zeile in „IP-Erlaubnisliste" wurde verworfen.',
                        '%d ungültige Zeilen in „IP-Erlaubnisliste" wurden verworfen.',
                        $invalid_count,
                        'creationell-captcha'
                    ),
                    $invalid_count
                ),
                'warning'
            );
        }
    }

    // code_challenge_watchlist: same shape as firewall_ip_allow — drop entries
    // that are not valid IPs or CIDR ranges. Watch-list IPs are NOT blocked,
    // they trigger the bild-code-challenge as additional verification.
    if ( isset( $clean['code_challenge_watchlist'] ) && is_array( $clean['code_challenge_watchlist'] ) ) {
        $valid_lines   = [];
        $invalid_count = 0;
        foreach ( $clean['code_challenge_watchlist'] as $line ) {
            if ( creationell_captcha_is_valid_ip_or_cidr( (string) $line ) ) {
                $valid_lines[] = (string) $line;
            } else {
                ++$invalid_count;
            }
        }
        $clean['code_challenge_watchlist'] = $valid_lines;
        if ( $invalid_count > 0 ) {
            add_settings_error(
                'creationell_captcha_settings',
                'code_challenge_watchlist_invalid',
                sprintf(
                    /* translators: %d is the number of dropped entries. */
                    _n(
                        '%d ungültige Zeile in „Watch-Liste" wurde verworfen.',
                        '%d ungültige Zeilen in „Watch-Liste" wurden verworfen.',
                        $invalid_count,
                        'creationell-captcha'
                    ),
                    $invalid_count
                ),
                'warning'
            );
        }
    }

    // interceptor_actions: enforce action-slug charset (a-z, 0-9, _, -, *)
    // with optional leading `!` for exclusion patterns. Delegates to the
    // shared validator so CLI and admin save go through the same rules.
    if ( isset( $clean['interceptor_actions'] ) && is_array( $clean['interceptor_actions'] ) ) {
        $valid_lines   = [];
        $invalid_count = 0;
        foreach ( $clean['interceptor_actions'] as $line ) {
            $line       = trim( (string) $line );
            $normalised = creationell_captcha_validate_action_pattern( $line );
            if ( null === $normalised ) {
                if ( '' !== $line ) {
                    ++$invalid_count;
                }
                continue;
            }
            $valid_lines[] = $normalised;
        }
        $clean['interceptor_actions'] = $valid_lines;
        if ( $invalid_count > 0 ) {
            add_settings_error(
                'creationell_captcha_settings',
                'interceptor_actions_invalid',
                sprintf(
                    /* translators: %d is the number of dropped entries. */
                    _n(
                        '%d ungültige Zeile in „Geschützte Aktionen" wurde verworfen.',
                        '%d ungültige Zeilen in „Geschützte Aktionen" wurden verworfen.',
                        $invalid_count,
                        'creationell-captcha'
                    ),
                    $invalid_count
                ),
                'warning'
            );
        }
    }

    // bypass_cookies: enforce strict name=value with alphanumeric name.
    // Delegates to the shared validator so CLI and admin save go through
    // the same rules.
    if ( isset( $clean['bypass_cookies'] ) && is_array( $clean['bypass_cookies'] ) ) {
        $valid_lines   = [];
        $invalid_count = 0;
        foreach ( $clean['bypass_cookies'] as $line ) {
            $line       = trim( (string) $line );
            $normalised = creationell_captcha_validate_cookie_entry( $line );
            if ( null === $normalised ) {
                if ( '' !== $line ) {
                    ++$invalid_count;
                }
                continue;
            }
            $valid_lines[] = $normalised;
        }
        $clean['bypass_cookies'] = $valid_lines;
        if ( $invalid_count > 0 ) {
            add_settings_error(
                'creationell_captcha_settings',
                'bypass_cookies_invalid',
                sprintf(
                    /* translators: %d is the number of dropped entries. */
                    _n(
                        '%d ungültige Zeile in „Cookie-Bypass" wurde verworfen.',
                        '%d ungültige Zeilen in „Cookie-Bypass" wurden verworfen.',
                        $invalid_count,
                        'creationell-captcha'
                    ),
                    $invalid_count
                ),
                'warning'
            );
        }
    }

    // Trusted-proxies: drop entries that are not valid IPs or CIDR ranges.
    if ( isset( $clean['firewall_trusted_proxies'] ) && is_array( $clean['firewall_trusted_proxies'] ) ) {
        $valid_lines   = [];
        $invalid_count = 0;
        foreach ( $clean['firewall_trusted_proxies'] as $line ) {
            if ( creationell_captcha_is_valid_ip_or_cidr( (string) $line ) ) {
                $valid_lines[] = (string) $line;
            } else {
                ++$invalid_count;
            }
        }
        $clean['firewall_trusted_proxies'] = $valid_lines;
        if ( $invalid_count > 0 ) {
            add_settings_error(
                'creationell_captcha_settings',
                'trusted_proxies_invalid',
                sprintf(
                    /* translators: %d is the number of dropped entries. */
                    _n(
                        '%d ungültige Zeile in „Vertrauenswürdige Proxies" wurde verworfen.',
                        '%d ungültige Zeilen in „Vertrauenswürdige Proxies" wurden verworfen.',
                        $invalid_count,
                        'creationell-captcha'
                    ),
                    $invalid_count
                ),
                'warning'
            );
        }
    }

    // Argon2id needs ext-sodium; refuse the selection otherwise.
    if ( 'argon2id' === $clean['algorithm'] && ! creationell_captcha_sodium_available() ) {
        $clean['algorithm'] = 'pbkdf2';
        add_settings_error(
            'creationell_captcha_settings',
            'argon2id_unavailable',
            __( 'Argon2id benötigt die PHP-Erweiterung „sodium" — es wurde auf PBKDF2 zurückgestellt.', 'creationell-captcha' ),
            'warning'
        );
    }

    // Create the event-log table when the detailed log is switched on.
    if ( ! empty( $clean['analytics_event_log'] ) ) {
        ( new \Creationell\Captcha\Analytics() )->ensure_table();
    }

    // Disabled fields don't submit values; without this restore, saving the
    // form silently resets every `requires`-gated field whose prerequisite
    // (chain) was off at render time.
    $stored      = get_option( 'creationell_captcha_settings', [] );
    $fields_spec = creationell_captcha_settings_fields();

    $was_enabled_at_render = static function ( string $k ) use ( &$was_enabled_at_render, $fields_spec, $stored ): bool {
        if ( ! is_array( $stored ) ) {
            return true;
        }
        if ( isset( $fields_spec[ $k ]['requires'] ) ) {
            $req = $fields_spec[ $k ]['requires'];
            if ( empty( $stored[ $req ] ?? null ) ) {
                return false;
            }
            return $was_enabled_at_render( $req );
        }
        if ( isset( $fields_spec[ $k ]['requires_select'] ) && is_array( $fields_spec[ $k ]['requires_select'] ) ) {
            foreach ( $fields_spec[ $k ]['requires_select'] as $other_key => $required_value ) {
                if ( ( $stored[ $other_key ] ?? null ) !== $required_value ) {
                    return false;
                }
            }
            return true;
        }
        return true;
    };

    foreach ( $fields_spec as $key => $field ) {
        if ( ! isset( $field['requires'] ) && ! isset( $field['requires_select'] ) ) {
            continue;
        }
        if ( $was_enabled_at_render( $key ) ) {
            continue;
        }
        if ( is_array( $stored ) && array_key_exists( $key, $stored ) ) {
            $clean[ $key ] = $stored[ $key ];
        }
    }

    // Preserve stored keys whose field is not in the current specification —
    // e.g. a per-plugin toggle while that plugin is temporarily inactive.
    if ( is_array( $stored ) ) {
        foreach ( $stored as $stored_key => $stored_value ) {
            if ( ! array_key_exists( $stored_key, $clean ) ) {
                $clean[ $stored_key ] = $stored_value;
            }
        }
    }

    return $clean;
}

/**
 * Renders the description shown at the top of the Proof-of-Work-Engine section.
 */
function creationell_captcha_render_engine_section(): void {
    echo '<p>' . esc_html__( 'Einstellungen für die Proof-of-Work-Sicherheitsabfrage. Der Browser muss eine kleine kryptografische Rechenaufgabe lösen, bevor das Formular abgeschickt werden darf — was für echte Nutzer in Millisekunden passiert, kostet Bots Sekunden. Die Lösung wird vom Server verifiziert; ein abgelaufenes oder gefälschtes Ergebnis führt zur Ablehnung.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the widget-appearance section.
 */
function creationell_captcha_render_widget_appearance_section(): void {
    printf(
        '<p>%s</p>',
        sprintf(
            /* translators: %s: link to the ALTCHA playground. */
            esc_html__( 'Erscheinungsbild und Verhalten der Sicherheitsabfrage. Zum Ausprobieren der Themes und Display-Modi vor dem Speichern: %s.', 'creationell-captcha' ),
            '<a href="https://playground.altcha.org/#/widget" target="_blank" rel="noopener noreferrer">ALTCHA-Playground</a>'
        )
    );
}

/**
 * Renders the description shown at the top of the code-challenge section.
 * Includes a warning notice when the PHP-GD extension is missing — without
 * it, image rendering cannot work and the trigger logic stays disabled.
 */
function creationell_captcha_render_code_challenge_section(): void {
    echo '<p>' . esc_html__(
        'Eine zweite Captcha-Stufe nach der Proof-of-Work-Verifikation: ein vom Server ausgestelltes Bild mit Code, das der User abtippt. Wird ausgespielt, sobald mindestens eine der unten konfigurierten Trigger-Bedingungen zutrifft (OR-Logik). Voraussetzung: PHP-GD-Extension.',
        'creationell-captcha'
    ) . '</p>';

    if ( ! extension_loaded( 'gd' ) ) {
        echo '<div class="notice notice-error inline"><p><strong>' . esc_html__(
            'Achtung:',
            'creationell-captcha'
        ) . '</strong> ' . esc_html__(
            'Die PHP-GD-Extension ist auf diesem Server nicht verfügbar. Das Bild-Code-Challenge-Feature ist deaktiviert, bis die Extension installiert wird.',
            'creationell-captcha'
        ) . '</p></div>';
    }
}

/**
 * Renders the description shown at the top of the core-forms section.
 */
function creationell_captcha_render_core_forms_section(): void {
    echo '<p>' . esc_html__( 'Proof-of-Work-Schutz für die mitgelieferten WordPress-Formulare.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the interceptor section.
 */
function creationell_captcha_render_interceptor_section(): void {
    echo '<p>' . esc_html__( 'Generischer serverseitiger Schutz für eigene Formular-Pfade — etwa für Theme- oder Custom-Formulare mit dem Shortcode [creationell_captcha].', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the form-plugins section.
 *
 * When no supported form plugin is active the section has no fields, so the
 * description doubles as a hint.
 */
function creationell_captcha_render_form_plugins_section(): void {
    $any_active =
        class_exists( 'WPCF7_ContactForm' )
        || class_exists( 'Forminator' )
        || class_exists( 'WPForms' )
        || class_exists( 'WooCommerce' );

    if ( $any_active ) {
        echo '<p>' . esc_html__( 'Automatischer Proof-of-Work-Schutz für die Formulare unterstützter Formular-Plugins.', 'creationell-captcha' ) . '</p>';
        return;
    }
    echo '<p>' . esc_html__( 'Kein unterstütztes Formular-Plugin aktiv. Sobald Contact Form 7, Forminator, WPForms oder WooCommerce aktiviert ist, erscheint hier der zugehörige Schalter.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the proxy section.
 */
function creationell_captcha_render_proxy_section(): void {
    echo '<p>' . esc_html__( 'IP-Ermittlung hinter Reverse-Proxies/CDNs. Der weitergeleitete Header wird nur akzeptiert, wenn die direkte Verbindung selbst aus einem vertrauenswürdigen Hop kommt.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the bypass section.
 */
function creationell_captcha_render_bypass_section(): void {
    echo '<p>' . esc_html__( 'Anfragen, die einem dieser Bypass-Einträge entsprechen, werden vom gesamten Schutz ausgenommen — Firewall, Rate-Limiter, Captcha und Under-Attack-Modus.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the firewall section.
 */
function creationell_captcha_render_firewall_section(): void {
    echo '<p>' . esc_html__( 'IP- und User-Agent-Firewall. Anfragen werden abgewiesen, bevor WordPress sie verarbeitet. CIDR-Notation ist erlaubt: 203.0.113.4 trifft genau eine IP, 203.0.113.0/24 einen ganzen 256-Adressen-Block, 203.0.113.0/29 acht aufeinanderfolgende Adressen.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the rate-limiting section.
 */
function creationell_captcha_render_ratelimit_section(): void {
    echo '<p>' . esc_html__( 'Begrenzt die Anzahl der Anfragen je IP-Adresse innerhalb eines Zeitfensters.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the under-attack section.
 */
function creationell_captcha_render_underattack_section(): void {
    echo '<p>' . esc_html__( 'Notfall-Modus für Bot-Angriffe: Anonyme Besucher müssen vor dem Zugriff eine Sicherheitsabfrage bestehen.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the under-attack appearance section.
 */
function creationell_captcha_render_underattack_appearance_section(): void {
    echo '<p>' . esc_html__( 'Optional — bei leeren Feldern werden die Standardwerte verwendet. Eigene CSS-Regeln greifen nach dem Default-Stylesheet und können beliebige Selektoren überschreiben.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the analytics section.
 */
function creationell_captcha_render_analytics_section(): void {
    echo '<p>' . esc_html__( 'Aufzeichnung der Sicherheitsereignisse. Die aggregierte Tagesstatistik läuft immer; der detaillierte Event-Log ist optional. Auswertung unter „CreaCaptcha → Statistik".', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders the description shown at the top of the email-protection section.
 */
function creationell_captcha_render_email_section(): void {
    echo '<p>' . esc_html__( 'Schutz von E-Mail-Adressen vor Spam-Harvestern. Adressen werden im Seitenquelltext verschleiert und erst im Browser wiederhergestellt.', 'creationell-captcha' ) . '</p>';
}

/**
 * Renders a single settings field.
 *
 * @param array<string, mixed> $args Field arguments (key + field spec).
 */
function creationell_captcha_render_field( array $args ): void {
    $key      = (string) $args['key'];
    $settings = creationell_captcha_get_settings();
    $value    = $settings[ $key ] ?? '';
    $name     = 'creationell_captcha_settings[' . $key . ']';

    // Field-level disable via the optional `requires` (boolean prerequisite)
    // or `requires_select` ({other_key => required_value} mapping) keys.
    // NB: do NOT name this $disabled — the select branch reuses that name
    // for a per-option flag (e.g. argon2id when ext-sodium is missing).
    $requires       = isset( $args['requires'] ) ? (string) $args['requires'] : '';
    $field_disabled = '';
    if ( '' !== $requires && empty( $settings[ $requires ] ) ) {
        $field_disabled = ' disabled';
    } elseif ( isset( $args['requires_select'] ) && is_array( $args['requires_select'] ) ) {
        foreach ( $args['requires_select'] as $other_key => $required_value ) {
            if ( ( $settings[ $other_key ] ?? null ) !== $required_value ) {
                $field_disabled = ' disabled';
                break;
            }
        }
    }

    switch ( $args['type'] ) {
        case 'select':
            echo '<select name="' . esc_attr( $name ) . '" id="' . esc_attr( $name ) . '"' . esc_attr( $field_disabled ) . '>';
            foreach ( $args['options'] as $opt_value => $opt_label ) {
                $disabled = '';
                $label    = (string) $opt_label;
                if ( 'algorithm' === $key && 'argon2id' === $opt_value && ! creationell_captcha_sodium_available() ) {
                    $disabled = ' disabled';
                    $label   .= ' — ' . __( 'ext-sodium nicht verfügbar', 'creationell-captcha' );
                }
                printf(
                    '<option value="%s"%s%s>%s</option>',
                    esc_attr( (string) $opt_value ),
                    selected( (string) $value, (string) $opt_value, false ),
                    esc_attr( $disabled ),
                    esc_html( $label )
                );
            }
            echo '</select>';
            break;

        case 'number':
            printf(
                '<input type="number" name="%s" id="%s" value="%s" min="%d" max="%d" class="small-text"%s />',
                esc_attr( $name ),
                esc_attr( $name ),
                esc_attr( (string) $value ),
                (int) $args['min'],
                (int) $args['max'],
                esc_attr( $field_disabled )
            );
            break;

        case 'checkbox':
            printf(
                '<label><input type="checkbox" name="%s" value="1"%s%s /> %s</label>',
                esc_attr( $name ),
                checked( ! empty( $value ), true, false ),
                esc_attr( $field_disabled ),
                esc_html__( 'Aktiviert', 'creationell-captcha' )
            );
            break;

        case 'color':
            // Hex-Color-Input. Die wp-color-picker-Initialisierung
            // erfolgt zentral in assets.php; alle .creationell-captcha-color
            // -Inputs werden dort per jQuery.wpColorPicker() initialisiert.
            printf(
                '<input type="text" name="%s" id="%s" value="%s" class="creationell-captcha-color"%s />',
                esc_attr( $name ),
                esc_attr( $name ),
                esc_attr( (string) $value ),
                esc_attr( $field_disabled )
            );
            break;

        case 'text':
            // Single-line plain-text input (anders als `textarea` für Listen
            // und `textblock` für Mehrzeiler).
            printf(
                '<input type="text" name="%s" id="%s" value="%s" class="regular-text"%s />',
                esc_attr( $name ),
                esc_attr( $name ),
                esc_attr( (string) $value ),
                esc_attr( $field_disabled )
            );
            break;

        case 'textblock':
            // Multi-Line-Textblock ohne zeilenweise List-Semantik
            // (anders als der bestehende `textarea`-Typ). Inhalt wird
            // 1:1 als String gespeichert und gerendert.
            printf(
                '<textarea name="%s" id="%s" rows="8" class="large-text code"%s>%s</textarea>',
                esc_attr( $name ),
                esc_attr( $name ),
                esc_attr( $field_disabled ),
                esc_textarea( (string) $value )
            );
            break;

        case 'textarea':
            $lines = is_array( $value ) ? array_map( 'strval', $value ) : [];
            printf(
                '<textarea name="%s" id="%s" rows="6" class="large-text code"%s>%s</textarea>',
                esc_attr( $name ),
                esc_attr( $name ),
                esc_attr( $field_disabled ),
                esc_textarea( implode( "\n", $lines ) )
            );
            break;
    }

    if ( ! empty( $args['help'] ) ) {
        echo '<p class="description">' . esc_html( (string) $args['help'] ) . '</p>';
    }
}
