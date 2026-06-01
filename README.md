# CreaCaptcha

**Plugin Name:** CreaCaptcha  
**Plugin URI:** https://github.com/creationell-dev/creationell-captcha  
**Description:** Datenschutzfreundlicher Proof-of-Work-Captcha, Firewall, Rate-Limiter, Under-Attack-Modus, E-Mail-Obfuskation und Bild-Code-Challenge — vollständig selbst-gehostet ohne externe Dienste.  
**Version:** 1.0.0  
**Author:** creationell® – die Werbeagentur <marketing@creationell.de>  
**Author URI:** https://www.creationell.de/  
**Contributors:** creationell-dev, JPKCom  
**Tags:** captcha, spam, anti-spam, anti-bot, proof of work  
**Requires at least:** 6.9  
**Tested up to:** 7.0  
**Requires PHP:** 8.3  
**Stable tag:** 1.0.0  
**License:** GPL-2.0-or-later  
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html  
**Text Domain:** creationell-captcha  
**Domain Path:** /languages

Schützt WordPress-Formulare und ganze Sites mit einem selbst-gehosteten Proof-of-Work-Captcha, Firewall, Rate-Limiter, Under-Attack-Interstitial, E-Mail-Obfuskation und optionaler Bild-Code-Challenge — ohne externe Dienste.

---

## Description

**CreaCaptcha** ist ein vollständig selbst-gehostetes Schutz-Plugin für WordPress. Es kombiniert einen Proof-of-Work-Captcha auf Basis der MIT-Bibliothek `altcha-org/altcha` mit einer Firewall, einem per-IP-Rate-Limiter, einem Under-Attack-Modus, E-Mail-Obfuskation und einer optionalen Bild-Code-Challenge. Es gibt keine externen API-Aufrufe, kein Lizenz-Gate, keine SaaS-Anbindung und keine Telemetrie — alle Funktionen laufen lokal in WordPress.

Das Plugin schützt die vier WordPress-Kernformulare (Kommentare, Login, Registrierung, Passwort-Reset) sowie automatisch alle Formulare gängiger Form-Plugins (**Contact Form 7**, **Forminator**, **WPForms**, **WooCommerce** mit Checkout / My-Account-Login / Registrierung / Lost-Password). Eigene oder fremde Formulare lassen sich über den Shortcode `[creationell_captcha]`, das Template-Tag `creationell_captcha_widget()` oder den generischen Interceptor (Pfad-Schutz) absichern.

### Key Features

- **Proof-of-Work-Captcha** — Server stellt eine Challenge aus, Browser löst sie mit PBKDF2/SHA-256 oder Argon2id; kein Klick-Puzzle, keine Bilderkennung, keine Tracking-Cookies
- **Vollständig selbst-gehostet** — Keine externen Dienste, kein API-Key, kein Lizenz-Server. Datenfluss bleibt zu 100 % auf dem WordPress-Host
- **Schutz der WordPress-Kernformulare** — Kommentare, Login, Registrierung und Passwort-Reset einzeln zuschaltbar
- **Vier Form-Plugin-Integrationen** — Contact Form 7, Forminator, WPForms, WooCommerce (Checkout + My-Account-Login + Registrierung + Lost-Password) mit Auto-Inject und Server-Verifikation
- **Generischer Interceptor** — Eigene Form-Pfade per URL-Muster (mit `*`-Wildcards und `!`-Ausschluss) schützen, fail-closed
- **Action-Schutz** — `admin-post.php` / `admin-ajax.php`-Aktionen über die `action`-Liste absichern, mit `*`-Wildcards und `!`-Ausschluss
- **Inject-Pfade** — Auf konfigurierten Pfaden wird die Sicherheitsabfrage automatisch in jedes `</form>` injiziert (idempotent — bereits geschützte Formulare werden übersprungen)
- **Shortcode & Template-Tag** — `[creationell_captcha]` oder `creationell_captcha_widget()` für freihändigen Einbau in beliebige Formulare; CF7-Form-Tag mit identischem Namen
- **Bild-Code-Challenge** — Optionale zweite Stufe nach PoW: serverseitig gerendertes PNG (PHP-GD, mitgelieferte DejaVu-TTF), 4–8-stelliger Code mit Anti-OCR-Verzerrung; Trigger wahlweise Immer, Under-Attack, Rate-Limit-Schwelle oder Watch-Liste (OR-verknüpft)
- **Under-Attack-Modus** — HTTP-503-Interstitial mit invisiblem PoW-Widget für anonyme Besucher; HMAC-signiertes Pass-Cookie für die konfigurierte Dauer
- **Firewall** — IP-Blocklist & -Allowlist (exakt + CIDR, v4 & v6), User-Agent-Blocklist (Wildcard), Proxy-Modus mit konfigurierbarem Forwarded-Header
- **Vertrauenswürdige Proxies** — Eigene IP-/CIDR-Liste, Cloudflare-IP-Auto-Refresh aus den offiziellen Listen, optionaler Trust von Private-Netzen; nur dann wird `X-Forwarded-For` ausgewertet
- **Rate-Limit** — Per-IP Fixed-Window-Counter mit drei Scopes (Core-Formulare / alle Formulare / global); konfigurierbarer Max-Wert, Fenster und Retry-After
- **Drei Bypass-Mechaniken** — IP-Allowlist (CIDR), User-Agent-Wildcard-Liste und Cookie-Bypass (`name=wert`); Treffer umgehen Firewall, Rate-Limit, Captcha und Under-Attack
- **Analytics & Event-Log** — Aggregierte Tages- und Stundenzähler je Ereignistyp (`verified` / `failed` / `firewall` / `ratelimit` / `underattack` / `challenge`); optional detaillierte Event-Tabelle mit IP, Pfad, Plugin, Aktion, Form-ID, Grund, User-Agent, Referrer, User-ID und Request-Body-Fingerprint
- **DSGVO-konforme IP-Anonymisierung** — Standard: IPv4 auf das letzte Oktett, IPv6 auf die letzten 80 Bit trunkiert
- **Statistik-Dashboard** — Drei Tabs (Übersicht / Verlauf / Ereignisse), vier Zeitfenster (24 h / 7 Tage / 30 Tage / 90 Tage), Filterleiste, seitenweises Blättern und CSV-Export
- **E-Mail-Obfuskation** — Verschleiert `mailto:`-Links und Klartextadressen per XOR-Hex; zwei Modi (Content-Filter oder Ganzseiten-Buffer für theme-hartkodierte Adressen)
- **Widget-Customization** — Anzeigemodus (Standard / schwebend / Overlay / Bar / Invisible), Interaktionstyp, Auto-Trigger, Theme, Branding-Toggle, Akzentfarbe, eigenes CSS und Strings-Override für alle Übersetzungstexte
- **Backend-UI mit sechs Tabs** — Captcha, Formulare, Firewall, Under-Attack, **Analytics**, E-Mail-Schutz — alles unter einem gemeinsamen „Änderungen speichern"
- **Werkzeuge-Seite** — Export / Import der Einstellungen als JSON, vollständiger Werksreset und ein gesonderter „Standardwerte laden"-Schritt (Listen bleiben erhalten)
- **WP-CLI-Integration** — Befehlsgruppe `wp creacaptcha` für Status, Diagnose, Modul-Aktivierung, Listen, Event-Log, Cloudflare-Refresh und Bypass-Tests
- **Self-Hosted-Updater** — Updates direkt aus GitHub-Releases mit SHA-256-Manifest-Verifikation (timing-safe `hash_equals`)
- **Kein Lizenz-Gate** — Alle Funktionen sind dauerhaft aktiv. GPL-2.0-or-later

---

## Installation

1. Den Plugin-Ordner `creationell-captcha` nach `/wp-content/plugins/` hochladen — entweder als ZIP über **Plugins → Installieren → Plugin hochladen** oder per FTP/SSH/`wp plugin install`.
2. Unter **Plugins → Installierte Plugins** das Plugin **CreaCaptcha** aktivieren.
3. Den neuen Menüpunkt **CreaCaptcha** im WordPress-Adminbereich öffnen.
4. Unter **CreaCaptcha → Einstellungen** im Tab **Captcha** den Master-Toggle prüfen (Standard: aktiv) und den Tab **Formulare** durchgehen, um WordPress-Kernformulare und Form-Plugins zu aktivieren.
5. Falls eigene Formular-Pfade abgesichert werden sollen: im Tab **Captcha → Interceptor** die Liste **Geschützte Pfade** pflegen.
6. Empfohlen: einmal **CreaCaptcha → Statistik** öffnen, damit der Event-Log aktiviert werden kann (optional — die Aggregat-Statistik läuft auch ohne).

### Anforderungen

- WordPress **6.9** oder höher
- PHP **8.3** oder höher
- Für die Bild-Code-Challenge: PHP-Erweiterung **GD**
- Für den optionalen Argon2id-Algorithmus: PHP-Erweiterung **Sodium**

Das Plugin prüft die Mindestversionen beim Aktivieren und zeigt im Admin-Bereich eine deutliche Hinweisleiste, wenn die Umgebung zu alt ist.

### Updates

Updates kommen direkt aus dem GitHub-Repo. Der eingebaute Self-Hosted-Updater (`includes/class-plugin-updater.php`) prüft regelmäßig das Manifest, vergleicht Versionen und installiert das offiziell signierte ZIP samt SHA-256-Checksum.

---

## Dokumentation

| Ressource | URL |
|-----------|-----|
| Plugin-Dokumentation (Web) | https://creationell-dev.github.io/creationell-captcha/ |
| Update-Manifest (JSON) | https://creationell-dev.github.io/creationell-captcha/plugin_creationell-captcha.json |
| API-Referenz (PHPDoc) | https://creationell-dev.github.io/creationell-captcha/docs/api/ |

Das Plugin aktualisiert sich über das Update-Manifest selbst — es ist kein
Eintrag im WordPress.org-Plugin-Verzeichnis erforderlich.

---

## Konfiguration

Sämtliche Einstellungen liegen unter **CreaCaptcha → Einstellungen** und sind in sechs Tabs gegliedert. Alle Tabs teilen ein gemeinsames „Änderungen speichern".

### Tab: Captcha

Steuert die Proof-of-Work-Engine, das Widget-Aussehen und die Bild-Code-Challenge.

#### Section „Engine"

| Option | Beschreibung |
|--------|--------------|
| Captcha aktivieren | Master-Toggle. Aus = keinerlei PoW-Verifikation; alle anderen Module bleiben unbeeinflusst |
| Algorithmus | `pbkdf2` (Standard, kein PHP-Extension-Bedarf) oder `argon2id` (benötigt `ext-sodium`) |
| Schwierigkeit | Anzahl PoW-Iterationen; Standard 50.000 (≈ 1 s auf Mittelklasse-Hardware) |
| Challenge-Gültigkeit | Sekunden, in denen eine ausgestellte Challenge eingelöst werden kann (Replay-Schutz) |

#### Section „WordPress-Kernformulare"

Vier unabhängige Toggles für Kommentare, Login, Registrierung und Passwort-Reset.

#### Section „Widget-Erscheinungsbild"

| Option | Beschreibung |
|--------|--------------|
| Anzeigemodus | `standard` / `floating` (schwebend über Submit-Button) / `overlay` / `bar` / `invisible` |
| Interaktionstyp | `checkbox` / `switch` / `native` |
| Auto-Trigger | `none` / `onload` / `onsubmit` |
| Theme | Eines der acht ALTCHA-v3-Themes |
| ALTCHA-Branding ausblenden | Versteckt Footer und Logo |
| Akzentfarbe | Color-Picker; wird als CSS-Variable `--creationell-captcha-primary` ausgespielt |
| Eigenes CSS | Wird inline nach dem Theme-CSS ausgegeben — beliebige Überschreibungen möglich |
| Übersetzungstexte überschreiben | JSON-Map zum Überschreiben einzelner Widget-Strings |
| Floating-Anchor | CSS-Selektor für den Anker des schwebenden Modus (leer = erster Submit-Button) |
| Floating-Position | `auto` / `top` / `bottom` |
| Floating-Offset | Abstand in Pixel (0–200) |

Die Floating-Felder sind nur aktiv, wenn der Anzeigemodus auf **schwebend** steht — sonst werden sie ausgegraut.

**Sprache:** CreaCaptcha erkennt die Widget-Sprache automatisch aus der
WordPress-Locale (`get_locale()`) und enqueued die passende von 20
vendorierten ALTCHA-Locale-Dateien (DE, EN, FR-FR/CA, ES-ES/419,
IT, NL, PT-PT/BR, PL, CS, SK, DA, SV, FI, NB, HU, RO, EL). Eine
nicht abgedeckte WP-Locale lässt das Widget auf seine eigene
`<html lang>`/Browser-Sprach-Detection bzw. Englisch zurückfallen.
Einzelne Begriffe lassen sich weiterhin über das Setting
**Übersetzungstexte überschreiben** anpassen — Auto-Locale und
Override greifen kombiniert, der Override gewinnt pro Schlüssel.

#### Section „Bild-Code-Challenge"

| Option | Beschreibung |
|--------|--------------|
| Code-Challenge aktivieren | Master-Toggle. Benötigt PHP-GD |
| Trigger: Immer | Spielt die Code-Challenge bei jedem Captcha-Request aus (Test / pauschal erhöhte Sicherheit) |
| Trigger: Under-Attack-Modus | Greift nur bei aktivem Under-Attack-Modus (außer auf dem Interstitial selbst — dort ist sie unterdrückt) |
| Trigger: Rate-Limit-Schwelle | Greift, sobald die IP die Rate-Limit-Auslastung von 50–95 % überschreitet |
| Trigger: Watch-Liste | IPs/CIDRs, die immer eine Code-Challenge bekommen |
| Code-Länge | 4–8 Zeichen |
| Zeichensatz | Nur Ziffern / alphanumerisch / alphanumerisch ohne Verwechsler (0-O, 1-I-l) |
| Token-Gültigkeit | 60–900 Sekunden |
| Anzeige-Modus | `standard` / `overlay` / `bottomsheet` (im Modal des Widgets) |

Mehrere Trigger sind OR-verknüpft. Wenn die Code-Challenge eingerichtet, aber GD nicht verfügbar ist, deaktiviert sich das Feature stillschweigend und zeigt eine Warn-Notice.

#### Section „Interceptor"

| Option | Beschreibung |
|--------|--------------|
| Geschützte Pfade | URL-Pfade mit `*`-Wildcard. `!`-Präfix kehrt das Muster um (Ausschluss). Eine Zeile pro Muster |
| Geschützte Aktionen | WordPress-Action-Namen für `admin-post.php`/`admin-ajax.php` (`$_POST[action]` / `$_GET[action]`). `*` und `!` werden unterstützt. Überschreibt den `is_admin`-Bypass |
| Inject-Pfade | Pfade, auf denen die Sicherheitsabfrage automatisch vor jedem `</form>` eingefügt wird (idempotent) |
| Bei eingeloggten Usern überspringen | Bypass für angemeldete User mit `edit_posts`-Capability |

Der Interceptor läuft als früher Request-Guard auf `init` und arbeitet **fail-closed**: Fehlt eine Verifikation, wird die Anfrage abgelehnt (HTTP 403, AJAX-Requests bekommen JSON-403).

### Tab: Formulare

Vier Toggles für die WordPress-Kernformulare (siehe Captcha-Tab — werden hier als Komfort-Kopie gespiegelt) sowie sechs Toggles für die Form-Plugin-Integrationen.

| Option | Beschreibung |
|--------|--------------|
| Contact Form 7 schützen | Aktiv, wenn CF7 installiert ist. Auto-Inject vor Submit, Verify über `wpcf7_spam` |
| Forminator schützen | Aktiv, wenn Forminator installiert ist. Auto-Inject + Verify über `forminator_custom_form_submit_errors` |
| WPForms schützen | Aktiv, wenn WPForms installiert ist. Auto-Inject vor Submit, Verify über `wpforms_process` |
| WooCommerce schützen | Master-Toggle. Aktiv, wenn WooCommerce installiert ist |
| → Checkout schützen | Auto-Inject auf `woocommerce_review_order_before_submit`, Verify auf `woocommerce_after_checkout_validation` |
| → My-Account-Login schützen | Auto-Inject auf `woocommerce_login_form_end`, Verify auf `woocommerce_process_login_errors` |
| → Registrierung schützen | Auto-Inject auf `woocommerce_register_form`, Verify auf `woocommerce_registration_errors` |
| → Lost-Password schützen | Render-only — Server-Verify läuft über das Kern-Modul `protect_password_reset` |

CF7 bietet zusätzlich einen Form-Tag `[creationell_captcha]`, mit dem die Position der Sicherheitsabfrage frei wählbar ist. Forminator/WPForms nutzen Auto-Inject standardmäßig vor dem Submit-Button — der Filter `creationell_captcha_forminator_autoinject` (bzw. `creationell_captcha_wpforms_autoinject`) erlaubt das Deaktivieren je Formular.

> **Hinweis:** WooCommerce-Produktbewertungen sind WordPress-Kommentare und werden bereits durch **WordPress-Kommentare schützen** abgedeckt. Es gibt absichtlich keinen separaten Sub-Toggle.

### Tab: Firewall

Vier Sections in dieser Reihenfolge: Proxy → Firewall → Bypass → Rate-Limit.

#### Section „Proxy & IP-Ermittlung"

| Option | Beschreibung |
|--------|--------------|
| Proxy-Modus | Aktivieren, wenn die Site hinter einem Reverse-Proxy / CDN liegt |
| Forwarded-Header | `X-Forwarded-For` (Standard) / `X-Real-IP` / `CF-Connecting-IP` / `True-Client-IP` |
| Vertrauenswürdige Proxies | IP-/CIDR-Liste, eine pro Zeile. Nur diese Hops dürfen den Forwarded-Header setzen |
| Cloudflare-IPs vertrauen | Cloudflare-v4 + v6-Ranges automatisch laden |
| Cloudflare-Auto-Refresh | Täglicher Cron-Refresh aus den offiziellen Cloudflare-Listen |
| Private Netze vertrauen | RFC1918 + ULA als trusted Hops behandeln |

Zusätzlich kann die wp-config-Konstante `CREATIONELL_CAPTCHA_TRUSTED_PROXIES` (Array von CIDRs) die Trust-Liste ergänzen.

#### Section „Firewall"

| Option | Beschreibung |
|--------|--------------|
| Firewall aktivieren | Master-Toggle |
| IP-Blockliste | Eine pro Zeile, exakt oder CIDR (v4 + v6) |
| IP-Erlaubnisliste | Global wirksam: umgeht Firewall, Rate-Limiter, Captcha und Under-Attack |
| User-Agent-Blockliste | Wildcard-Muster (z. B. `*bot*`, `*scanner*`) |

#### Section „Bypass"

Drei Eintragsarten, die jeweils Firewall, Rate-Limit, Captcha und Under-Attack-Modus umgehen.

| Option | Beschreibung |
|--------|--------------|
| User-Agent-Erlaubnisliste | Wildcard-Muster für Allow-listing (z. B. eigene Monitoring-Bots) |
| Cookie-Bypass | Liste im Format `name=wert`, eine pro Zeile |

Treffer auf Formular-Ebene erscheinen im Event-Log als `verified`-Eintrag mit passendem Grund (IP-Allowlist / UA-Bypass / Cookie-Bypass).

#### Section „Rate-Limit"

| Option | Beschreibung |
|--------|--------------|
| Rate-Limit aktivieren | Master-Toggle |
| Maximale Anfragen | Fixed-Window-Limit pro IP, Standard 30 |
| Zeitfenster | Sekunden des Fensters, Standard 300 |
| Wirkungsbereich | `core` (nur Kernformulare) / `forms` (alle Formulare) / `all` (global, alle Anfragen) |
| `edit_posts`-Exemption | Eingeloggte User mit Schreibrechten ausnehmen |

Bei Überschreitung sendet der Plugin-Stack HTTP 429 mit `Retry-After`-Header.

### Tab: Under-Attack

| Option | Beschreibung |
|--------|--------------|
| Under-Attack aktivieren | Master-Toggle. Bei `an` muss jeder anonyme Besucher eine PoW-Sicherheitsabfrage bestehen, bevor er die Site erreicht |
| Pass-Dauer | Lebenszeit des HMAC-signierten Pass-Cookies in Sekunden |
| Eingeloggte Besucher ausnehmen | Standard: aktiv |

`wp-admin`, REST-API und Cron sind automatisch ausgenommen. Der Kill-Switch `CREATIONELL_CAPTCHA_DISABLE` (wp-config-Konstante) hebt den Modus global auf.

#### Section „Erscheinungsbild"

Optional — leere Felder verwenden die Standardwerte. Sichtbar, sobald
der Under-Attack-Modus aktiv ist (sonst ausgegraut).

| Option | Beschreibung |
|--------|--------------|
| Logo-URL | Bild über der Überschrift, zentriert, Höhe ≤ 128 px. Default: kein Logo. Alt-Text = Website-Name. Über `.crea-ua-logo` im Eigenes-CSS-Feld feinjustierbar |
| Browser-Tab-Titel | `<title>`-Tag der Interstitial-Seite. Default: „Sicherheitsprüfung" |
| Überschrift | Große H1 mittig auf der Seite. Default: „Die Website wird gerade besonders geschützt" |
| Hinweistext | Erläuternder Text unter der Überschrift. Default: „Ihr Browser wird kurz geprüft — einen Moment bitte." |
| NoScript-Hinweis | Nur sichtbar bei deaktiviertem JS. Default: „Für die Sicherheitsprüfung muss JavaScript aktiviert sein." |
| Hintergrundfarbe | Hex, z. B. `#0a0a0a`. Default: `#f0f0f1` |
| Textfarbe | Hex, z. B. `#ffffff`. Default: `#1d2327` |
| Eigenes CSS | Beliebige CSS-Regeln. Werden nach dem Default-Stylesheet ausgegeben und überschreiben alles. Verfügbare CSS-Variablen: `--creationell-captcha-ua-bg`, `--creationell-captcha-ua-text`. Verfügbare Selektoren: `body`, `.crea-ua`, `.crea-ua h1`, `.crea-ua p`, `.crea-ua noscript`, `.crea-ua-logo` |

### Tab: Analytics

| Option | Beschreibung |
|--------|--------------|
| Event-Log aktivieren | Schreibt jede Aktion in die Tabelle `<prefix>creationell_captcha_events`. Aggregierte Tageszähler laufen immer |
| Aufbewahrungsdauer | Tage, nach denen Event-Log-Einträge gelöscht werden (Default 30) |
| IP-Adressen anonymisieren | DSGVO-First: trunkiert IPv4 auf das letzte Oktett, IPv6 auf die letzten 80 Bit (Default: an) |
| Request-Body-Fingerprint speichern | JSON-Map aus Feldnamen und Wertlängen — ohne die Werte selbst. Sensitive Feldnamen (`password`, `secret`, `token`, `iban`, `api_key`, `cvv`, …) werden zusätzlich gehasht |
| Erfolgreiche Verifikationen loggen | Per-Event-Typ-Schalter, Default: an |
| Fehlgeschlagene Verifikationen loggen | Default: an |
| Firewall-Blocks loggen | Default: an |
| Rate-Limit-Blocks loggen | Default: an |
| Under-Attack-Abfragen loggen | Default: an |
| Bestandene Under-Attack-Prüfungen loggen | Default: an |
| Ausgestellte Challenges loggen | Default: **aus** (hochvolumig) |

### Tab: E-Mail-Schutz

| Option | Beschreibung |
|--------|--------------|
| E-Mail-Adressen verschleiern | Master-Toggle |
| Verschleierungsmodus | `content` (Filter auf `the_content` / `the_excerpt` / `widget_text` / `widget_block_content` / `comment_text`) oder `buffer` (Vollseiten-Ausgabepuffer) |

Im Buffer-Modus werden auch theme-hartkodierte `mailto:`-Links und Klartextadressen im Footer/Header erfasst. `<head>`, `<script>` und `<style>` bleiben unberührt. Feed-Requests und der Admin-Bereich umgehen die Obfuskation immer.

---

## Shortcode & Template-Tag

### `[creationell_captcha]`

Bettet das ALTCHA-Widget an beliebiger Stelle ein.

| Attribut | Werte | Default |
|----------|-------|---------|
| `class` | CSS-Klassen | — |

Bei aktiviertem CF7-Plugin ist `[creationell_captcha]` zusätzlich als CF7-Form-Tag verfügbar und kann direkt im CF7-Form-Editor platziert werden.

### `creationell_captcha_widget()`

Template-Tag mit identischer Wirkung. Nützlich, wenn ein Shortcode nicht in Frage kommt (z. B. in Theme-PHP-Templates):

```php
<form method="post">
    <!-- … Felder … -->
    <?php creationell_captcha_widget(); ?>
    <button type="submit">Senden</button>
</form>
```

Bei serverseitiger Verifikation immer auch den Pfad in **Geschützte Pfade** eintragen (siehe nächster Abschnitt) — sonst läuft eine manipulierte Submission ungeprüft durch.

---

## Geschützte Pfade & Interceptor

Der Interceptor läuft auf `init` und ist die generische Schutzschicht für **eigene** Formulare. Konfiguriert wird er im Captcha-Tab.

### Pfad-Muster

`[creationell_captcha]`-Shortcode und Template-Tag rendern nur das Widget. Die Server-Verifikation übernimmt der Interceptor anhand der Pfad-Liste.

```
/kontakt              ← exakt
/forms/*              ← Wildcard
!/forms/whitelisted   ← Ausschluss (mit ! kombinierbar)
```

`!`-Muster greifen vor positiven Mustern. So lässt sich `/forms/*` schützen, ein einzelner Sub-Pfad aber gezielt freistellen.

### Action-Schutz

Für AJAX-/Admin-Post-Endpoints reicht die Pfad-Liste nicht — Requests gehen alle an `admin-ajax.php` oder `admin-post.php`. Die Liste **Geschützte Aktionen** wertet stattdessen das `action`-Feld (POST oder GET) aus:

```
my-custom-action
form/*
!form/internal
```

Action-Treffer überschreiben den `is_admin()`-Bypass — die Verifikation läuft auch dann, wenn der Aufruf aus dem Admin-Backend käme.

### Auto-Inject auf Pfaden

Die **Inject-Pfade**-Liste fügt die Sicherheitsabfrage automatisch vor jedem `</form>` der passenden Seite ein, ohne dass das Theme oder ein Plugin angepasst werden muss. Idempotent: Formulare mit bereits eingebautem Widget bleiben unangetastet.

### Bypass-Kette

Vor jeder Verifikation läuft die Bypass-Kette in dieser Reihenfolge:

1. Kill-Switch `CREATIONELL_CAPTCHA_DISABLE` (wp-config-Konstante)
2. Master-Toggle aus
3. Request-Methode `GET` (Renderpfad — Verify nur auf POST/PUT/DELETE/PATCH)
4. CLI / Cron / XML-RPC (nicht-Browser-Kontexte)
5. `is_admin()` — **wird durch Action-Schutz überschrieben**, sobald die `action` auf einer geschützten Liste steht
6. REST-API-Eigen-Endpoints (Challenge-/Code-Routes)
7. WordPress-Kernformulare (siehe Tab Formulare)
8. `edit_posts`-Capability (eingeloggte User)
9. Bei aktiviertem Toggle: alle eingeloggten User
10. Globale Bypass-Quellen: IP-Allowlist, UA-Allowlist, Cookie-Bypass

Greift einer der Schritte, wird die Anfrage durchgelassen. Auf Formular-Ebene wird der erfolgreiche Bypass als `verified`-Event mit Grund-Annotation geloggt.

### Entwickler-Filter

```php
// Pfad/Action-Listen runtime ergänzen
add_filter( 'creationell_captcha_interceptor_paths', function ( array $paths ): array {
    $paths[] = '/api/mein-form/*';
    return $paths;
} );

add_filter( 'creationell_captcha_interceptor_actions', function ( array $actions ): array {
    $actions[] = 'mein_plugin_form';
    return $actions;
} );

// Eigenen Bypass anhängen (true = durchlassen)
add_filter( 'creationell_captcha_interceptor_bypass', function ( bool $bypass ): bool {
    return $bypass || ( defined( 'MY_DEV_BYPASS' ) && MY_DEV_BYPASS );
} );

// Custom geschützten Pfad zur Laufzeit registrieren
creationell_captcha_protect_path( '/checkout/step2' );
```

---

## Bild-Code-Challenge

Die Bild-Code-Challenge ist eine **zweite Stufe** nach der PoW-Verifikation — kein Ersatz. Der Browser löst zuerst die PoW, der Server schickt dann optional ein PNG mit einem 4–8-stelligen Code, den der Nutzer abtippt.

### Trigger-Bedingungen

| Trigger | Wirkung |
|---------|---------|
| Immer | Pauschal aktiv bei jedem Captcha-Request |
| Under-Attack-Modus | Greift nur, wenn UA-Modus aktiv ist (außer auf dem Interstitial — dort unterdrückt) |
| Rate-Limit-Schwelle | Greift ab konfigurierter Auslastung (50–95 %) der IP-Bucket |
| Watch-Liste | IPs/CIDRs, die immer eine Code-Challenge bekommen |

Mehrere Trigger sind OR-verknüpft.

### REST-Endpoints

| Methode | Route | Zweck |
|---------|-------|-------|
| `GET` | `/wp-json/creationell-captcha/v1/code-image?t=<token>` | PNG-Bild ausliefern (Cache-Header `no-store`) |
| `POST` | `/wp-json/creationell-captcha/v1/code-verify` | Code prüfen, signierte ALTCHA-Payload zurückgeben |

Tokens sind opake 32-Hex-Server-Identifier; der erwartete Code lebt nur in einem WP-Transient und verlässt den Server nie. Die zurückgegebene Payload geht durch den bestehenden Verify-Pfad.

### Rendering

PHP-GD mit vendorierter DejaVuSans-Bold-TTF (`assets/fonts/captcha.ttf`) und naiver Anti-OCR-Verzerrung (rotierte Zeichen, Querlinien, Rauschen). Fehlt die TTF, fällt der Renderer auf den GD-Bitmap-Font 5 zurück.

Fehlt **GD selbst**, deaktiviert sich das Feature stillschweigend und der Section-Renderer zeigt eine Warn-Notice.

### Bypass-Schutz

`Engine::verify()` lehnt jeden Payload ab, in dem `parameters.data.ccode` clientseitig gesetzt ist — ein Angreifer kann den originalen Payload nicht recyclen, um die Code-Stufe zu überspringen.

---

## Under-Attack-Modus

Der Under-Attack-Modus ist ein **Notfall-Schalter** für aktive Bot-Wellen. Bei aktivem Modus liefert WordPress für jeden anonymen Besucher ein HTTP-503-Interstitial mit einem invisiblen ALTCHA-Widget aus. Erst nach bestandener PoW-Sicherheitsabfrage setzt der Server ein HMAC-signiertes Pass-Cookie und lässt den Browser auf die eigentliche Seite.

### Ablauf

1. Anonymer Besucher öffnet beliebige Seite
2. `template_redirect` fängt den Request ab, zeigt das Interstitial
3. Browser löst die PoW-Sicherheitsabfrage im Hintergrund
4. Server prüft, signiert das Pass-Cookie `creationell_captcha_ua_pass` (HMAC, gültig für die konfigurierte Pass-Dauer)
5. Browser wird mit `Location`-Header auf die ursprüngliche URL umgeleitet
6. Folgende Requests passieren den Modus, bis das Cookie abläuft

`wp-admin`, REST-API und Cron sind automatisch ausgenommen — die Site bleibt von innen administrierbar. Eingeloggte User sind per Default ebenfalls ausgenommen.

### Kill-Switch

Definiert man `define( 'CREATIONELL_CAPTCHA_DISABLE', true );` in `wp-config.php`, sind alle CreaCaptcha-Funktionen — inklusive Under-Attack — global deaktiviert. Praktisch für den Fall, dass die Site sich selbst aussperrt.

---

## Statistik & Event-Log

### Aggregat-Statistiken

Immer aktiv, datenschutzfreundlich, keine personenbezogenen Daten. Zwei Counter-Tabellen in `wp_options`:

- `creationell_captcha_analytics` — Tageszähler je Ereignistyp
- `creationell_captcha_analytics_hourly` — Stundenzähler je Ereignistyp (für die 24-h-Sicht)

### Detail-Event-Log

Optional, schaltbar im Analytics-Tab. Schreibt in die eigene Tabelle `<prefix>creationell_captcha_events` mit 15 Spalten:

| Spalte | Inhalt |
|--------|--------|
| `id` | Auto-Increment |
| `event_type` | `verified` / `failed` / `firewall` / `ratelimit` / `underattack` / `underattack_passed` / `challenge` |
| `created_at` | UTC-Zeitstempel |
| `ip` | Client-IP (anonymisiert, wenn konfiguriert) |
| `path` | Request-Pfad (REQUEST_URI ohne Query-Args — keine GET-Token im Log) |
| `user_id` | WordPress-User-ID (falls eingeloggt) |
| `user_agent` | UA-String |
| `referrer` | HTTP-Referer |
| `plugin` | Auslösendes Modul (`cf7` / `forminator` / `wpforms` / `wc-checkout` / …) |
| `action` | Action-Name (bei admin-post/admin-ajax) |
| `form_id` | Plugin-spezifische Form-ID (z. B. WPForms-/Forminator-ID) |
| `interceptor` | Interceptor-Pfadmuster, das gegriffen hat |
| `reason` | Klartext-Grund (z. B. „IP-Allowlist", „Replay-Schutz", „PoW-Hash falsch") |
| `verification_data` | Eingereichter Captcha-Payload (gekürzt) |
| `request_body` | Body-Fingerprint (JSON-Map Feldname → Wertlänge; sensitive Felder gehasht) |

### Statistik-Dashboard

**CreaCaptcha → Statistik** liefert drei Tabs:

| Tab | Inhalt |
|-----|--------|
| Übersicht | Vier KPI-Kacheln für die letzten 24 h (Captcha gelöst, Abgewehrt = Firewall + Rate-Limit, Under-Attack Abfragen/bestanden, Captcha fehlgeschlagen) plus thematisch gruppierte Vergleichstabellen (Formular-Captchas / Abgewehrte Zugriffe / Under-Attack-Modus / Technisch) über vier Zeitfenster (24 h / 7 Tage / 30 Tage / 90 Tage) |
| Verlauf | Zeitreihen-Plot je Ereignistyp über das gewählte Fenster |
| Ereignisse | Filterbare Tabelle der Detail-Events, seitenweise (50/Seite), mit Detail-Modal je Eintrag und CSV-Export der gefilterten Menge |

Die Filter-Leiste im Ereignisse-Tab kombiniert Freitextsuche (IP + Pfad), Ereignistyp-Filter und Von/Bis-Datumsbereich.

### Performance

Seit v0.26.0:

- `Analytics::record()` sammelt Counter-Deltas in Class-Statics und flusht sie auf `shutdown` in einem einzigen `get_option`/`update_option`-Paar je Counter-Tabelle — statt zwei Roundtrips pro Event
- Composite-Index `event_type_created (event_type, created_at)` auf der Events-Tabelle: typgefilterte Range-Queries laufen als reiner Index-Range-Scan ohne Filesort
- `creationell_captcha_get_settings()` cacht das Default-Merge-Ergebnis pro Request

---

## E-Mail-Schutz (Obfuskation)

### Zwei Modi

| Modus | Wirkung |
|-------|---------|
| Content | `the_content`, `the_excerpt`, `widget_text`, `widget_block_content`, `comment_text` durchlaufen `EmailObfuscator::process()` |
| Buffer | Ganzseiten-`ob_start()` auf `template_redirect` — `EmailObfuscator::process_page()` verarbeitet den gesamten `<body>` |

### Verschleierung

`mailto:`-Hrefs werden zu `href="#" data-cce="<hex>"`, Klartext-Adressen zu `<span data-cce="<hex>">[E-Mail-Adresse — bitte JavaScript aktivieren]</span>`. Der Hex-String ist eine XOR-Verschlüsselung der Adresse mit einem einmaligen Per-Page-Key.

### Decoder

`assets/js/email-obfuscation.js` läuft auf `DOMContentLoaded`, bindet sich auf alle `[data-cce]`-Elemente und stellt die Original-Adresse im Browser wieder her.

### Ausnahmen

`<head>`, `<script>`, `<style>` werden im Buffer-Modus übersprungen. Feed-Requests, `wp-admin` und der Kill-Switch umgehen die Obfuskation immer.

---

## WP-CLI

Alle Plugin-Funktionen sind per `wp creacaptcha` automatisierbar. Eine Übersicht aller Befehle:

```
wp help creacaptcha
```

### Betriebsbefehle

| Befehl | Zweck |
|--------|-------|
| `wp creacaptcha status` | Übersicht: Kill-Switch, Module, Listengrößen, Proxy/CF-Trust, Code-Challenge, Watchlist, Form-Plugin-Toggles |
| `wp creacaptcha info` | Diagnose: Plugin-Version, Lib-Version, Algorithmus, HMAC-Secrets vorhanden, Event-Log-Tabelle |
| `wp creacaptcha stats [--window=24h\|7d\|30d\|90d\|all]` | Analytics-Kennzahlen für das gewählte Fenster |
| `wp creacaptcha enable <feature>` | Modul/Feature aktivieren (siehe unten) |
| `wp creacaptcha disable <feature>` | Modul/Feature deaktivieren |
| `wp creacaptcha repair` | Selbstheilung: fehlende Secrets generieren, Event-Log-Tabelle anlegen, Default-Keys ergänzen |
| `wp creacaptcha doctor` | Pflicht-Checks: Lib, Secrets, Tabelle, Cron, Konflikte, PHP-/GD-/Sodium-Versionen, Settings-Defaults |
| `wp creacaptcha test-bypass [--ip=…] [--ua=…] [--cookie=…]` | Simuliert die Bypass-Auswertung; Exit 0 bei Bypass, Exit 1 sonst |

Die `<feature>`-Schlüssel für `enable`/`disable`: `captcha`, `comments`, `login`, `registration`, `password-reset`, `cf7`, `forminator`, `wpforms`, `woocommerce`, `wc-checkout`, `wc-login`, `wc-registration`, `wc-lost-password`, `firewall`, `ratelimit`, `under-attack`, `analytics`, `event-log`, `email-obfuscation`, `code-challenge`.

### Einstellungen

| Befehl | Zweck |
|--------|-------|
| `wp creacaptcha settings list` | Alle Settings mit aktuellen Werten ausgeben |
| `wp creacaptcha settings get <key>` | Einen Wert lesen |
| `wp creacaptcha settings set <key> <value>` | Einen Wert setzen (bool / int / text / color / textblock / list / json) |
| `wp creacaptcha settings export [--file=…]` | JSON-Export aller Settings |
| `wp creacaptcha settings import --file=…` | JSON-Import |
| `wp creacaptcha settings reset` | Voller Werksreset inklusive aller Listen |
| `wp creacaptcha settings load-defaults` | Nur Konfigwerte zurücksetzen, Listen bleiben |

### Listen-Pflege

Jede Liste hat denselben Subcommand-Baukasten: `add <eintrag>`, `remove <eintrag>`, `list`, `clear`.

| Befehl | Liste |
|--------|-------|
| `wp creacaptcha blocklist …` | IP-Blockliste |
| `wp creacaptcha allowlist …` | IP-Erlaubnisliste (global wirksam) |
| `wp creacaptcha ua-blocklist …` | User-Agent-Blockliste |
| `wp creacaptcha paths …` | Geschützte Pfade |
| `wp creacaptcha actions …` | Geschützte Aktionen |
| `wp creacaptcha inject-paths …` | Inject-Pfade |
| `wp creacaptcha trusted-proxies …` | Vertrauenswürdige Proxies |
| `wp creacaptcha bypass-ua …` | UA-Bypass-Liste |
| `wp creacaptcha bypass-cookies …` | Cookie-Bypass (`name=wert`) |
| `wp creacaptcha watchlist …` | Code-Challenge-Watchlist |

### Cloudflare-Cache

| Befehl | Zweck |
|--------|-------|
| `wp creacaptcha cloudflare refresh` | CF-v4/v6-Ranges aktualisieren |
| `wp creacaptcha cloudflare status` | Status des CF-Caches (Anzahl Ranges, letzter Refresh, nächster Cron, Quelle) |
| `wp creacaptcha cloudflare clear` | CF-Cache leeren |

Der ältere Alias `wp creacaptcha refresh-cloudflare-ips` bleibt vorerst als Deprecation-Alias erhalten.

### Event-Log

| Befehl | Zweck |
|--------|-------|
| `wp creacaptcha log list [--fields=…] [--format=…] [--limit=…]` | Event-Log-Einträge auflisten; ohne `--fields` 4-Spalten-Default, mit `--fields=` alle 15 Spalten verfügbar |
| `wp creacaptcha log show <id>` | Einen Event mit allen 15 Spalten anzeigen |
| `wp creacaptcha log clear` | Event-Log komplett leeren |
| `wp creacaptcha log prune` | Alte Einträge gemäß Aufbewahrungsdauer löschen |

Die Werkzeuge-Seite im Backend (siehe nächster Abschnitt) bietet dieselben Export-/Import-/Reset-/Load-Defaults-Aktionen.

---

## Werkzeuge

**CreaCaptcha → Werkzeuge** ist die Backend-Entsprechung der wichtigsten CLI-Aktionen. Fünf Karten:

| Karte | Aktion |
|-------|--------|
| Einstellungen exportieren | Lädt alle Settings als JSON-Datei herunter |
| Einstellungen importieren | JSON-Upload, Validierung gegen das Settings-Schema |
| Standardwerte laden | Konfigwerte auf Default zurücksetzen; **Listen bleiben unverändert** |
| Auf Werkseinstellungen zurücksetzen | Voller Werksreset inklusive aller Listen (mit Warn-Box und Confirm-Dialog) |
| Cloudflare-IP-Cache | Status + Buttons „Jetzt aktualisieren" und „Cache leeren" |

---

## Developer Reference

Die wichtigsten Konstanten, Hooks und Filter im Überblick:

### Konstanten (wp-config.php überschreibbar)

| Konstante | Default | Zweck |
|-----------|---------|-------|
| `CREATIONELL_CAPTCHA_VERSION` | `'1.0.0'` | Plugin-Version |
| `CREATIONELL_CAPTCHA_FILE` | `__FILE__` | Plugin-Hauptdatei |
| `CREATIONELL_CAPTCHA_PLUGIN_PATH` | `plugin_dir_path(...)` | Plugin-Ordner |
| `CREATIONELL_CAPTCHA_PLUGIN_URL` | `plugin_dir_url(...)` | Plugin-URL |
| `CREATIONELL_CAPTCHA_MIN_PHP` | `'8.3'` | PHP-Mindestversion |
| `CREATIONELL_CAPTCHA_MIN_WP` | `'6.9'` | WordPress-Mindestversion |
| `CREATIONELL_CAPTCHA_DEBUG` | `WP_DEBUG` | Aktiviert Debug-Logging |
| `CREATIONELL_CAPTCHA_DISABLE` | _ungesetzt_ | Wenn `true`: globaler Kill-Switch — alle Module aus |
| `CREATIONELL_CAPTCHA_HMAC_SECRET` | _autogeneriert_ | Override für das Challenge-HMAC-Secret |
| `CREATIONELL_CAPTCHA_HMAC_KEY_SECRET` | _autogeneriert_ | Override für das HMAC-Key-Secret |
| `CREATIONELL_CAPTCHA_TRUSTED_PROXIES` | _ungesetzt_ | Array von zusätzlich vertrauenswürdigen Proxy-CIDRs |

### Hooks (Actions)

| Hook | Wann |
|------|------|
| `creationell_captcha_loaded` | Nach dem Plugin-Bootstrap, alle Module geladen |
| `creationell_captcha_deactivated` | Beim Deaktivieren des Plugins |
| `creationell_captcha_event` | Bei jedem Aggregat-Event-Bump (`$type`, `$context`) |
| `creationell_captcha_firewall_blocked` | Firewall hat eine IP/UA geblockt |
| `creationell_captcha_ratelimit_exceeded` | Rate-Limit für eine IP überschritten |
| `creationell_captcha_interceptor_blocked` | Interceptor hat eine Submission abgewiesen |
| `creationell_captcha_interceptor_passed` | Interceptor hat eine Submission durchgelassen |

### Hooks (Filter)

| Filter | Zweck |
|--------|-------|
| `creationell_captcha_interceptor_paths` | Pfad-Liste runtime modifizieren |
| `creationell_captcha_interceptor_actions` | Action-Liste runtime modifizieren |
| `creationell_captcha_interceptor_bypass` | Eigene Bypass-Logik anhängen (`true` = durchlassen) |
| `creationell_captcha_interceptor_guarded` | Modifiziert die Liste der „immer geschützten" Anker-Pfade |
| `creationell_captcha_firewall_block` | Eigene Block-Logik anhängen (`true` = blocken) |
| `creationell_captcha_forminator_autoinject` | Forminator-Autoinject je Formular toggeln (`bool`, `int $form_id`) |
| `creationell_captcha_wpforms_autoinject` | WPForms-Autoinject je Formular toggeln |
| `creationell_captcha_wc_checkout_autoinject` | WooCommerce-Checkout-Autoinject toggeln |
| `creationell_captcha_wc_login_autoinject` | WooCommerce-Login-Autoinject toggeln |
| `creationell_captcha_wc_registration_autoinject` | WooCommerce-Registrierungs-Autoinject toggeln |
| `creationell_captcha_wc_lost_password_autoinject` | WooCommerce-Lost-Password-Autoinject toggeln |
| `creationell_captcha_request_body_sensitive_patterns` | Sensitive Feldnamen-Patterns für die Body-Fingerprint-Maskierung erweitern |
| `creationell_captcha_doctor_checks` | Eigene Doctor-Checks zur WP-CLI-Diagnose ergänzen |

### REST-Endpoints

Alle Routes unter dem Namespace `creationell-captcha/v1`:

| Methode | Route | Zweck |
|---------|-------|-------|
| `GET` | `/challenge` | Neue PoW-Challenge ausstellen |
| `GET` | `/code-image?t=<token>` | PNG der Bild-Code-Challenge ausliefern |
| `POST` | `/code-verify` | Eingegebenen Code prüfen, signierte ALTCHA-Payload zurückgeben |

### Wichtige PHP-Helper

```php
// Schutz für eigene Pfade registrieren
creationell_captcha_protect_path( '/checkout/step2' );

// Widget rendern (Template-Tag-Variante)
creationell_captcha_widget();

// Settings memoiziert laden
$settings = creationell_captcha_get_settings();

// Bypass-Auswertung manuell aufrufen
$bypass_active = creationell_captcha_request_bypassed();
```

### Architektur

Das Plugin folgt einer require-basierten Classic-WordPress-Architektur. Die Klassen liegen unter `Creationell\Captcha\…` in `includes/class-*.php`; prozedurale Bootstrap-Helper in `includes/<modul>.php`. Die geprefixte ALTCHA-Library landet via Strauss in `lib/Creationell\Captcha\Vendor\…`. Es gibt **keinen** Composer-Autoloader im Release-ZIP — alle Requires sind explizit.

---

## FAQ

### Sendet CreaCaptcha Daten an externe Dienste?

Nein. Das Plugin arbeitet vollständig selbst-gehostet — es gibt keine API-Aufrufe, kein Telemetrie-Backend, keinen Lizenz-Check und keine SaaS-Anbindung. Die einzige optionale externe Anfrage ist der Cloudflare-IP-Refresh aus den offiziellen Cloudflare-Listen, der ausschließlich auf expliziten Toggle läuft.

### Welcher Captcha-Algorithmus läuft im Hintergrund?

CreaCaptcha nutzt die offizielle MIT-Bibliothek `altcha-org/altcha`. Standardmäßig kommt PBKDF2/SHA-256 zum Einsatz (kein PHP-Extension-Bedarf). Optional lässt sich auf Argon2id umschalten, dafür wird `ext-sodium` benötigt.

### Funktioniert das Plugin ohne JavaScript?

Nein — die Proof-of-Work-Sicherheitsabfrage muss vom Browser gelöst werden. Ohne JavaScript erscheint das Widget als Hinweistext, und die Server-Verifikation wird die Submission abweisen. Für ein vollständig JS-loses Schutz-Setup ist die Firewall+Rate-Limit-Schicht der richtige Ansatz.

### Welche Form-Plugins werden unterstützt?

Mit dedizierten Integrationen: **Contact Form 7**, **Forminator**, **WPForms** (Lite und Pro), **WooCommerce** (Checkout, My-Account-Login, Registrierung, Lost-Password). Beliebige andere Formulare lassen sich über `[creationell_captcha]` und die Geschützte-Pfade-Liste absichern. Für AJAX-/Admin-Post-Endpoints gibt es zusätzlich die Geschützte-Aktionen-Liste.

### Wie schütze ich ein eigenes Formular auf einer beliebigen Seite?

Drei Schritte: (1) Den Shortcode `[creationell_captcha]` oder das Template-Tag `creationell_captcha_widget()` ins Formular einbauen. (2) Den Pfad der Seite oder den Submit-Pfad in **Captcha → Interceptor → Geschützte Pfade** eintragen. (3) Bei AJAX-/Admin-Post-Submissions zusätzlich den `action`-Namen in **Geschützte Aktionen**. Der Interceptor verifiziert dann automatisch jede Submission.

### Was passiert mit ungelösten Bot-Submissions?

Der Server lehnt die Submission ab. Bei klassischen Formularen erhält der Browser die normale Validierungs-Fehlermeldung des jeweiligen Plugins. Bei AJAX wird `403 Forbidden` mit JSON-Body geliefert. Der Bot bekommt keine Hilfe in Form von Hinweisen, woran das Captcha gescheitert ist — der `reason` landet nur im Event-Log.

### Wie kann ich mich selbst aussperren — und wie komme ich wieder rein?

Wer durch eigene Firewall-Regeln, Rate-Limit oder einen kaputten Under-Attack-Modus ausgesperrt wird, kann zu jeder Zeit per `wp-config.php` den Kill-Switch setzen:

```php
define( 'CREATIONELL_CAPTCHA_DISABLE', true );
```

Sofort sind **alle** Module aus — Firewall, Rate-Limit, Captcha, Under-Attack, Interceptor. Anschließend lassen sich die problematischen Einstellungen im Backend korrigieren. Ohne SSH/FTP-Zugriff bleibt der direkte Datenbank-Eingriff: `wp option update creationell_captcha_settings …` oder per `wp creacaptcha settings load-defaults`.

### Funktioniert das Plugin hinter Cloudflare oder einem Reverse-Proxy?

Ja. Im Tab **Firewall** unter „Proxy & IP-Ermittlung" den Proxy-Modus aktivieren und den passenden Forwarded-Header wählen. Für Cloudflare zusätzlich „Cloudflare-IPs vertrauen" und optional den Auto-Refresh einschalten — die offiziellen Cloudflare-v4/v6-Ranges werden dann täglich neu geladen. Ohne Trust-Konfiguration wird der Header ignoriert, damit Angreifer nicht beliebige IPs spoofen können.

### Wie viel Performance kostet das Plugin?

Sehr wenig. Die Captcha-Berechnung läuft im Browser, nicht auf dem Server. Die Firewall-Auswertung ist eine reine IP-/Pattern-Prüfung (keine externen Lookups). Analytics-Counter werden seit v0.26.0 pro Request gesammelt und in einem einzigen DB-Roundtrip auf `shutdown` geschrieben. Das Event-Log nutzt seit derselben Version einen Composite-Index, der typgefilterte Dashboard-Queries ohne Filesort beantwortet.

### Wie DSGVO-konform ist das Plugin?

Out-of-the-box ist die IP-Anonymisierung im Event-Log aktiv (IPv4 auf letztes Oktett, IPv6 auf letzte 80 Bit trunkiert). Aggregat-Zähler enthalten keinerlei personenbezogene Daten. Im Event-Log werden keine Query-String-Werte (GET-Token, Magic-Links, API-Keys) gespeichert — der Pfad wird vor dem Schreiben auf den reinen Pfadanteil reduziert. Request-Body-Fingerprints enthalten nur Feldnamen und Wertlängen; sensitive Feldnamen werden zusätzlich gehasht.

### Wie deaktiviere ich das Plugin sauber?

Über **Plugins → Installierte Plugins** deaktivieren reicht für den Betrieb. Wer auch die Daten loswerden will, kann das Plugin anschließend löschen — der `uninstall.php`-Cleanup entfernt alle Options, Transients (inklusive `_cc_*`-Caches und `_git_update_*`-Locks) sowie die Event-Tabelle.

### Funktioniert das Plugin mit Multisite?

Ja, allerdings pro Site einzeln aktivierbar. Es gibt aktuell keine Network-Activate-Logik mit zentralen Settings — jede Site hat ihre eigene Konfiguration. Network-weite Aktivierung ist möglich, hat aber denselben Effekt wie eine Aktivierung pro Site.

### Kann ich CreaCaptcha parallel zu einem anderen Captcha-Plugin betreiben?

Technisch ja — die Code-Pfade kollidieren nicht. `wp creacaptcha doctor` prüft auf bekannte Captcha-Plugins (reCAPTCHA, hCaptcha, Turnstile, ALTCHA-WordPress) und warnt, weil zwei Captcha-Layer auf demselben Formular für den Nutzer unzumutbar werden. Empfehlung: nur eines aktiv lassen.

### Wo finde ich Logs, wenn etwas nicht funktioniert?

Mit `define( 'CREATIONELL_CAPTCHA_DEBUG', true );` (oder global `WP_DEBUG`) schreibt das Plugin Debug-Hinweise nach `wp-content/debug.log`. Zusätzlich liefert `wp creacaptcha doctor` einen kompletten Diagnose-Lauf, und das Event-Log zeigt alle abgewiesenen Requests samt Grund.

### Wie aktualisiere ich auf eine neue Version?

Drei Wege: (1) Der eingebaute Self-Hosted-Updater zeigt neue Versionen automatisch im **Plugins**-Bildschirm — wie ein normales wp.org-Update. (2) ZIP von der GitHub-Release-Seite herunterladen und manuell über **Plugins → Installieren → Plugin hochladen** einspielen. (3) Per WP-CLI: `wp plugin install --activate <release-url>` mit der URL aus den GitHub-Releases.

---

## Changelog

### 1.0.0

Erstes stabiles Release. CreaCaptcha ist ein vollständig selbst-gehosteter
Spamschutz für WordPress — ohne externe Dienste, ohne Tracking, ohne
Lizenz-Gate.

Funktionsumfang:

- Proof-of-Work-Captcha (ALTCHA-kompatibel, PBKDF2/Argon2id) für Kommentare,
  Login, Registrierung und Passwort-Reset
- Formular-Integrationen: Contact Form 7, Forminator, WPForms, WooCommerce
  (Checkout, Login, Registrierung, Lost-Password)
- Generischer Interceptor für beliebige URL-Pfade und WordPress-Actions
- Firewall (IP-/CIDR-/User-Agent-Listen), per-IP-Rate-Limiter, Proxy-Support
  inkl. Cloudflare
- Under-Attack-Modus mit anpassbarer 503-Interstitial-Seite (Texte, Farben,
  Logo, Custom-CSS)
- Bild-Code-Challenge als optionale zweite Captcha-Stufe
- E-Mail-Obfuskation (Content-Filter oder Ganzseiten-Buffer)
- Statistik-Dashboard, Event-Log mit Suche/Filter/CSV-Export
- Umfassende WP-CLI-Integration (`wp creacaptcha …`)
- Widget-Anpassung (Themes, Farben, Custom-CSS, 20 Sprachen)

Neu in diesem Release:

- Plugin-Banner für den WordPress-Update-Screen
- Dokumentations-Sektion in der README (Web-Doku, Update-Manifest,
  API-Referenz)
- Contributors-Angabe im Update-Manifest erweitert

Das Update von v0.30.x erfolgt ohne Datenbank-Migration und ohne Breaking
Changes — bestehende Einstellungen, Listen und Statistiken bleiben
unverändert erhalten.

### 0.30.1

Wartungsrelease: Release-Infrastruktur umgestellt — keine funktionalen
Änderungen am Plugin.

- Die Plugin-Releases werden ab dieser Version aus dem dedizierten,
  öffentlichen Release-Repository
  `github.com/creationell-dev/creationell-captcha` veröffentlicht.
  Download-, Update- und Dokumentations-URLs bleiben unverändert.
- Build-Pipeline gehärtet: GitHub-Actions und phpDocumentor auf feste
  Versionen gepinnt, Build-Staging vom Paketinhalt ausgeschlossen.

### 0.30.0

Under-Attack Pass-Event & Statistik-Übersicht — das Backend unterscheidet
jetzt, ob ein Besucher die Under-Attack-Prüfung bestanden hat oder hängen
blieb, und die Statistik-Übersicht erklärt ihre Zahlen selbst.

- Neuer Event-Typ `underattack_passed`: feuert, wenn ein Besucher die
  Under-Attack-PoW-Prüfung löst und das Pass-Cookie ausgestellt wird.
  Erscheint in Übersicht, Verlauf, Ereignis-Filter, CSV-Export und WP-CLI
  (`wp creacaptcha stats`, `log list --type=underattack_passed`).
- Neues Log-Gate „Bestandene Under-Attack-Prüfungen loggen" (Default: an);
  Aggregat-Zähler laufen unabhängig davon.
- Statistik-Übersicht: vier KPI-Kacheln statt drei — „Abgewehrt (24 h)"
  zählt nur noch echte Blocks (Firewall + Rate-Limit), Under-Attack hat
  eine eigene Kachel „Abfragen / bestanden".
- Statistik-Übersicht: die flache Ereignis-Tabelle ist in vier thematische
  Gruppen mit Erklärungstext gegliedert (Formular-Captchas / Abgewehrte
  Zugriffe / Under-Attack-Modus / Technisch); nicht zugeordnete Typen
  landen automatisch in einer Auffanggruppe „Weitere Ereignisse".
- Keine DB-Migration nötig; bestehende Events und Zähler bleiben
  unverändert gültig.

### 0.29.0

Logo im Under-Attack-Interstitial — die 503-Seite kann jetzt ein Logo
oberhalb der Überschrift anzeigen.

- Neues optionales Feld „Logo-URL" in der Under-Attack-Section
  „Erscheinungsbild". Leer = kein Logo (Default); bestehende Sites
  sehen ohne Aktion keine Änderung.
- `UnderAttack::serve_interstitial()` reicht die URL als `$logo_url`
  ans Template; das Template rendert ein zentriertes
  `<img class="crea-ua-logo">` vor dem `<h1>`, gedeckelt auf
  `max-height: 128px`. Alt-Text = Website-Name (`get_bloginfo('name')`).
- Sanitization via `esc_url_raw()` beim Speichern entschärft
  gefährliche Schemata (`javascript:` o. Ä.); Ausgabe zusätzlich mit
  `esc_url()`.
- Größe per `.crea-ua-logo` über das vorhandene „Eigenes CSS"-Feld
  überschreibbar. Setzbar über `wp creacaptcha settings set
  underattack_logo_url <url>`.

### 0.28.0

Feature-Modul 21 — Under-Attack-Customization: Wording und
Erscheinungsbild der Interstitial-Seite sind ab sofort über das
Backend konfigurierbar, ohne Plugin-Code zu patchen.

- Neue Section „Erscheinungsbild" im Under-Attack-Tab mit sieben
  optionalen Feldern: vier Texte (Browser-Tab-Titel, Überschrift,
  Hinweistext, NoScript-Hinweis), zwei Farben (Hintergrund,
  Textfarbe) und ein freies Custom-CSS-Feld.
- Renderer in `UnderAttack::serve_interstitial()` baut die drei
  Variablen `$texts` / `$colors` / `$user_css` und reicht sie ans
  Template weiter; leere Felder fallen auf die existierenden
  Hartcode-Defaults zurück.
- Template (`includes/under-attack-interstitial.php`) nutzt zwei
  neue CSS-Variablen `--creationell-captcha-ua-bg` und
  `--creationell-captcha-ua-text` für die Farben. Ein zweiter
  `<style>`-Block direkt nach dem Default-Stylesheet nimmt das
  Custom-CSS auf — alle Regeln des Defaults sind dort überschreibbar.
- Sanitization analog zu `widget_custom_css`: `wp_strip_all_tags()`
  neutralisiert `</style><script>`-Injection bevor der Wert die
  Template-Ausgabe erreicht.
- Alle sieben Felder sind über das bestehende
  `wp creacaptcha settings set <key> <value>`-CLI setzbar — neue
  Field-Typen waren nicht nötig, alle Typen (`text`, `color`,
  `textblock`) gibt es seit Modul 14.

Sites nach Update sehen ohne Aktion **keine** visuelle Veränderung —
alle sieben Felder sind initial leer und das Template fällt damit
auf die bisherigen Default-Werte zurück.

### 0.27.2

Metadaten-Anpassung an WordPress 7.0 / 6.9.

- **Plugin-Header & README:** `Requires at least` von 6.8 auf 6.9
  angehoben, `Tested up to` von 6.8 auf 7.0 nachgezogen. WordPress 7.0
  ist seit kurzem produktiv; der Plugin-Test-Lauf der bisherigen
  Module 1–20 ist gegen 7.0 sauber.
- **Konstante:** `CREATIONELL_CAPTCHA_MIN_WP` von `'6.8'` auf `'6.9'`
  angehoben. Sites auf WordPress 6.8 oder älter erhalten beim Aktivieren
  jetzt die bestehende Hinweisleiste „Erfordert WordPress 6.9 oder
  neuer." statt das Plugin zu laden.
- Inline-Kommentar im Plugin-Bootstrap (`WordPress 6.8+` →
  `WordPress 6.9+`) und die interne Entwickler-Dokumentation
  konsistent nachgezogen.

Keine funktionalen Code-Änderungen.

### 0.27.1

CSS-Fix: Widget-Abstand zum darauffolgenden Element im Standard-Modus.

- `assets/css/widget.css`: Die Block-Flow-Abstandsregel auf
  `<altcha-widget>` ist von `margin-block-end` auf `padding-block-end`
  umgestellt und auf den `display="standard"`-Modus eingeschränkt.
  Hintergrund: das Widget ist auf den geschützten Formularen
  typischerweise das letzte Kind im `<form>` — der bisherige
  `margin-block-end` kollabierte deshalb mit der Bottom-Kante des
  Form-Elements (kein `padding-bottom`/`border-bottom`/eigene BFC),
  sodass visuell überhaupt kein Abstand zum nachfolgenden Inhalt
  blieb. Padding kollabiert nicht — der konfigurierbare Abstand
  (Default jetzt `1rem` statt `1.5em`) ist daher zuverlässig sichtbar.
  Der CSS-Variablenname (`--creationell-captcha-widget-margin-block-end`)
  bleibt aus Kompatibilitätsgründen gleich.
- Floating/Overlay/Bar/Invisible-Modi bekommen den Abstand nicht mehr
  spurious mitgegeben — ihre eigentliche Widget-Darstellung ist
  position-fixed bzw. display:none, ein Inline-Spacer wäre dort nur
  ein toter 1.5em-Gap.

### 0.27.0

Feature-Modul 20 — Widget-i18n: Die Sicherheitsabfrage erscheint
endlich in der korrekten Sprache, ohne dass der Admin etwas
konfigurieren muss.

- Neue 20 vendorierte ALTCHA-Locale-Dateien unter
  `assets/js/altcha-i18n/` (DE, EN, FR-FR/CA, ES-ES/419, IT, NL,
  PT-PT/BR, PL, CS, SK, DA, SV, FI, NB, HU, RO, EL) — je ~3 KB,
  Page-Load lädt weiterhin nur eine Datei.
- Neuer Helper `creationell_captcha_resolve_widget_locale()` mit
  Lookup-Tabelle (48 WP-Locale-Strings, inkl. formal/informal-
  Varianten) auf 20 ALTCHA-Codes.
- `creationell_captcha_build_widget_markup()` enqueued die passende
  Locale-Datei lazy (analog zum Theme-CSS-Pattern) und setzt
  `language="<code>"` am `<altcha-widget>`. Locales ohne Mapping
  überspringen beide Schritte — das Widget nutzt dann seine eigene
  `<html lang>`/Browser-Detection.
- Zwei neue Filter `creationell_captcha_widget_locale_map` und
  `creationell_captcha_widget_locale` für Projekt-Overrides ohne
  Plugin-Patch.
- `wp creacaptcha status` zeigt eine neue Zeile „Widget-Sprache"
  mit dem effektiven ALTCHA-Code plus dem WP-Locale-Ursprung.
- `widget_strings_override` bleibt unverändert und greift weiterhin
  als Pro-Schlüssel-Override **on top** der Auto-Locale.

### 0.26.2

Bugfix-Release: schließt eine Verify-Regression aus v0.22.0 / Commit
`c322b96`, die seit der Korrektur des `configuration`-JSON-Attributs
das ALTCHA-Widget dazu brachte, bei jedem gelösten PoW die
`/code-verify`-Route aufzurufen — und dort mit 400 `invalid_request`
abgewiesen zu werden, weil im Plain-Mode (ohne Code-Challenge im
`/challenge`-Response) das `code`-Feld im Body fehlt.

- `includes/widget.php`: `verifyUrl` wird im `configuration`-JSON nur
  noch dann emittiert, wenn das Master-Setting `code_challenge_enabled`
  aktiv ist. Im Standardfall (Code-Challenge aus) verifiziert das
  Widget wieder rein client-seitig, ohne den überflüssigen
  Server-Roundtrip.
- `includes/code-challenge.php`: `/code-verify` akzeptiert das
  `code`-Feld jetzt als optional. Plain-Mode (`{ payload }` ohne
  `code`) durchläuft `Engine::verify_structural()`, prüft die
  Original-Signatur über den gleichen Single-Use-Transient-Schlüssel
  wie `Engine::verify()` (verhindert, dass eine einzelne gelöste PoW
  in N frische Payloads multipliziert wird) und gibt eine frische
  signierte Payload zurück. Code-Challenge-Modus bleibt funktional
  unverändert.

Die ALTCHA-`verifyUrl`-Mechanik schaltet das Widget pauschal in den
Server-Verify-Modus — auch ohne Code-Challenge im Response. Beide
Fixes zusammen: saubere Standard-Konfiguration ohne Roundtrip
*und* Defense-in-Depth, falls `code_challenge_enabled` aktiv ist
aber kein Trigger greift.

### 0.26.1

UX-Polish-Release: schließt die drei nicht-essenziellen UX-Befunde aus
dem Qualitäts-Audit (Modul 18) ab.

- Neue `requires_select`-Semantik im Settings-Schema: Felder können jetzt
  nicht nur an einen booleschen Vorbedingungs-Toggle gekoppelt werden
  (`requires => 'foo_enabled'`), sondern auch an einen konkreten Wert
  eines anderen Select-Feldes (`requires_select => ['widget_display' =>
  'floating']`). Render-Layer setzt `disabled`, Sanitizer-Cascade
  bewahrt den gespeicherten Wert. Anwendung: die drei Floating-Felder
  `widget_floating_anchor`/`widget_floating_placement`/
  `widget_floating_offset` werden jetzt nur aktiv geschaltet, wenn der
  Widget-Anzeige-Modus auf „Schwebend" steht — in jedem anderen Modus
  bleiben sie ausgegraut.
- Tools-Page „Auf Werkseinstellungen zurücksetzen": deutliche
  `notice-warning`-Box oberhalb der Karte mit Hinweis auf die
  Listen-Leerung und Verweis auf die ungefährliche „Standardwerte
  laden"-Karte.
- Wortwahl „Sicherheitsabfrage" (user-facing Help-Texte) vs. „Captcha"
  (technische/Admin-Kontexte wie Tab-Label, Section-Titel, Engine-
  Begriffe) bleibt bestehen — das Audit hat die aktuelle Trennung als
  akzeptabel eingestuft.

### 0.26.0

Performance-Release: drei aufgeschobene Optimierungen aus dem
Qualitäts-Audit (Modul 18) — Settings-Memoize, Analytics-Bump-Memoize
und ein Composite-Index auf der Events-Tabelle.

- `creationell_captcha_get_settings()` cacht das Ergebnis pro Request
  in einer statischen Variable. Bisher rief jede Modul-Komponente
  (Interceptor, Firewall, Rate-Limiter, Under-Attack, jede Form-
  Integration) die Funktion mehrfach pro Request, jedes Mal mit
  `array_merge` über ~70 Default-Keys. Invalidierung läuft über die
  `update_option`/`add_option`/`delete_option`-Hooks für
  `creationell_captcha_settings`, sodass Caller direkt nach einem
  Speichervorgang den frischen Wert sehen.
- `Analytics::record()` sammelt die Daily- und Hourly-Counter-Deltas in
  request-lokalen Static-Caches und flusht sie via
  `add_action('shutdown', …)` in genau einem
  `get_option`/`update_option`-Paar pro Counter-Tabelle. Vorher: zwei
  Roundtrips pro Event — eine `/challenge`-Route mit aktivem
  `log_challenge`-Toggle und nachgelagerter Verifikation kommt damit
  bei 4–6 Roundtrips an. Jetzt: maximal 2 Roundtrips, unabhängig von
  der Anzahl der Events. Die Cutoff-Pruning-Logik wandert in
  `apply_deltas()` und läuft jetzt einmal je Counter statt einmal je
  Event. Konkurrente Updates aus parallelen Requests bleiben erhalten
  (Flush liest frischen Stand und addiert nur die eigenen Deltas).
- Composite-Index `event_type_created (event_type, created_at)` auf der
  Events-Tabelle. Dashboard-Queries mit `event_type`-Filter
  (Statistik-Tab, CSV-Export, Detail-Modal-Source) erzwangen bisher
  einen Filesort über den per-day-gesliceten Range. Mit dem
  Composite-Index läuft die typgefilterte Range-Abfrage als reiner
  Index-Range-Scan. Migration via `Analytics::ensure_table()` —
  dbDelta für Frischinstalls, `SHOW INDEX`-Guard plus `ALTER TABLE`
  als Fallback für bestehende Tabellen (dbDelta ist für Index-Adds
  historisch unzuverlässig). `%i`-Identifier-Platzhalter konsistent
  mit `clear_events()`.

### 0.25.0

Qualitäts-Audit-Release: Security-Härtung des Updaters, Event-Log-Privacy,
Body-Fingerprint-Maskierung sowie umfassende UX-Hilfetexte und Konsistenz-
Fixes im Backend.

**Sicherheit:**
- Updater (`includes/class-plugin-updater.php`): Checksum-Vergleich nutzt
  jetzt `hash_equals()` (timing-safe). Slug-Heuristik in
  `verify_download_checksum()` durch Exakt-Match gegen
  `manifest.download_url` ergänzt — verhindert Bypass über ein
  manipuliertes Manifest mit Slug-freier Download-URL. Manifest-Fetch über
  `wp_safe_remote_get()` (Defense-in-Depth gegen SSRF).
- Event-Log: `Analytics::current_path()` reduziert `REQUEST_URI` auf den
  Pfad-Anteil. GET-Token, Magic-Login-Links und API-Keys landen damit nicht
  mehr im persistenten Event-Log.
- Request-Body-Fingerprint: Feldnamen mit sensitiven Substrings
  (`password`, `secret`, `token`, `iban`, `api_key`, `cvv`, …) werden vor
  dem JSON-Encode durch `[masked:<sha256-8>]` ersetzt, um Custom-Form-
  Schemata nicht im Event-Log preiszugeben. Neuer Filter
  `creationell_captcha_request_body_sensitive_patterns` für
  projektspezifische Erweiterungen.
- `Analytics::clear_events()` nutzt jetzt `wpdb::prepare( 'DELETE FROM %i',
  $table )` statt Roh-Interpolation (WP-6.2+-konform).

**Backend-UX:**
- DSGVO-First: Default `analytics_anonymize_ip` von `false` auf `true`.
  Neue Installs anonymisieren IPs out-of-the-box; bestehende Installs
  behalten ihre Wahl.
- Rate-Limit-Default `ratelimit_max` von 10 auf 30 (besser für Login-Scope —
  ein Nutzer mit Tippfehler-Marathon läuft nicht mehr ins 5-Minuten-Lockout).
- Tab-Reihenfolge: „Analytics" steht nun vor „E-Mail-Schutz" (näher an den
  Schutzmodulen).
- Firewall-Tab: Sektionen sortiert auf Proxy → Firewall → Bypass →
  Rate-Limit (Bypass folgt der Firewall, deren Regeln sie überstimmt).
- `widget_code_challenge_display` in die Code-Challenge-Section verschoben
  und an `code_challenge_enabled` gekoppelt.
- 21 fehlende oder schwache Settings-Hilfetexte ergänzt (`algorithm`,
  `difficulty`, `challenge_expiry`, alle `widget_*`-Customization-Felder,
  Core-Forms-Toggles, alle Form-Plugin-Toggles, Rate-Limit-Felder,
  `firewall_proxy_header`, `firewall_ip_block`/`ua_block`, `underattack_enabled`,
  `analytics_event_log`, `bypass_cookies`, `firewall_cloudflare_auto_refresh`,
  `interceptor_skip_logged_in`). Section-Renderer für Engine, Code-Challenge
  und Firewall mit erklärenden Texten ergänzt (PoW-Konzept,
  OR-Logik der Trigger, CIDR-Notation).
- `interceptor_actions`-Hilfetext nennt jetzt die `edit_posts`-Exemption
  (Autoren/Editoren weiterhin ausgenommen).
- Tools-Page: Reset-Karte + Confirm-Dialog erwähnen jetzt explizit auch
  Interceptor- und Bypass-Listen.

**WP-CLI:**
- `wp creacaptcha status` zeigt drei neue Zeilen: Proxy-Modus,
  CF-Trust / CF-Auto-Refresh und IP-Anonymisierung.
- `wp creacaptcha doctor` prüft `ext-sodium`, wenn der Algorithmus auf
  Argon2id steht — Error mit Fix-Vorschlag, wenn die Extension fehlt.

**Code-Qualität:**
- `defined( constant_name: 'ABSPATH' )` → `defined( 'ABSPATH' )` in
  48 Dateien. Named-Args auf PHP-Builtins sind nicht stabilitäts-garantiert
  und werden von Static-Analyzern als Anti-Pattern geflaggt.
- PHPDoc: über 20 eigene `do_action`/`apply_filters`-Hooks vollständig
  dokumentiert (`creationell_captcha_event`, Interceptor-Filter-Familie,
  WPForms-/WC-Autoinject-Filter), Repeat-Dispatches mit WordPress-Core-
  style „This action is documented in …"-Verweisen.
- REST-Callback-PHPDocs in `includes/rest.php` und
  `includes/code-challenge.php` ergänzt (`@param`/`@return` mit
  Status-Code-Tabelle).

**Tooling & Doku:**
- `phpdoc.xml` Version-Drift `0.1.0` → `0.25.0`.
- Plugin-Header-Description nennt jetzt Firewall, Rate-Limit, Under-Attack,
  E-Mail-Obfuskation und Code-Challenge (vorher: nur PoW-Spamschutz).
- README-Description um WPForms-, WooCommerce-Integrationen und
  Code-Challenge-Absatz erweitert.
- `uninstall.php`: Transient-Cleanup vom `_used_`-Prefix auf das gesamte
  `creationell_captcha_`-Prefix erweitert; entfernt jetzt auch `_cc_*`,
  `_rl_*` und `_git_update_*`-Caches/Locks.

**Behebt:**
- Inkorrekt formulierter IPv6-Anonymisierungs-Hilfetext (`includes/settings.php`):
  stimmt jetzt mit der Code-Logik überein (erste 48 Bit bleiben, letzte
  80 Bit auf 0).
- Tippfehler „mehrmietigen" → „mehrmandantigen (Shared Hosting)".
- `Tested up to: 6.9` → `6.8` (WordPress 6.9 ist Stand 2026-05-28 noch
  nicht released).

### 0.24.0

- WP-CLI-Nachzug Phase 2: schließt sieben CLI-Coverage-Lücken nach den
  Modulen 14–16.
- Neuer Listen-Befehl `wp creacaptcha watchlist add|remove|list|clear`
  für die Code-Challenge-Watchlist (`code_challenge_watchlist`).
- `wp creacaptcha status` zeigt sechs zusätzliche Zeilen: Form-Plugin-
  Toggles (CF7, Forminator, WPForms, WooCommerce + gruppierte Zeile für
  die vier Woo-Sub-Toggles) und den Watchlist-Eintragszähler.
- `wp creacaptcha enable code-challenge` / `disable code-challenge`
  togglet `code_challenge_enabled` über `feature_map()`. Doc-Strings
  von `enable`/`disable` listen jetzt alle 19 Features (vorher 12,
  fehlten WPForms, WooCommerce und die vier wc-* Mappings).
- `wp creacaptcha settings set` unterstützt jetzt zusätzlich die
  Feldtypen `text`, `color` und `textblock` — damit werden die
  Widget-Customization-Felder (`widget_floating_anchor`,
  `widget_primary_color`, `widget_custom_css`, `widget_strings_override`)
  über die CLI setzbar. Verworfene JSON-/Hex-Werte werden via
  `WP_CLI::warning()` gemeldet.
- `wp creacaptcha doctor` ergänzt einen GD-Extension-Check: wenn
  `code_challenge_enabled` aktiv ist, muss die PHP-GD-Extension geladen
  sein (sonst `error` mit Exit-Code 1).
- `wp creacaptcha log list` unterstützt jetzt `--fields=` (WP-CLI-
  Standard); Default-Output bleibt die bisherige 4-Spalten-Übersicht,
  verfügbar werden alle 15 Spalten der Event-Log-Tabelle.
- Neuer Befehl `wp creacaptcha log show <id>` zeigt einen einzelnen
  Event mit allen 15 Spalten als Key-Value-Tabelle (oder JSON/YAML/CSV
  via `--format`).

### 0.23.0

- WPForms-Integration: Neues Setting „WPForms schützen" im Formulare-Tab.
  Aktiv, sobald das WPForms-Plugin installiert ist. Auto-Inject des
  Widgets vor dem Submit-Button (`wpforms_display_submit_before`); Verify
  über `wpforms_process`-Action, Fehlerausgabe via
  `wpforms()->process->errors[$form_id]['header']`.
- WooCommerce-Integration: Master-Toggle „WooCommerce schützen" plus vier
  Sub-Toggles für Checkout, My-Account-Login, My-Account-Registrierung
  und Lost-Password. Auto-Inject auf den nativen Woo-Hooks
  (`woocommerce_review_order_before_submit`, `woocommerce_login_form_end`,
  `woocommerce_register_form`, `woocommerce_lostpassword_form`); Verify
  auf `woocommerce_after_checkout_validation`,
  `woocommerce_process_login_errors`, `woocommerce_registration_errors`.
- Lost-Password ist Render-only: Server-Verifikation läuft über
  `protect_password_reset` (WordPress-Kernformular), weil Woo-Lost-Password
  über WP-Core `retrieve_password()` zurückläuft und damit
  `lostpassword_post` feuert.
- Produkt-Bewertungen werden bewusst nicht über einen eigenen Sub-Toggle
  abgebildet — Reviews sind WordPress-Kommentare und durch
  `protect_comments` abgedeckt; der Hilfetext am Master-Toggle weist
  darauf hin.
- Render-Override-Filter (alle fünf, einheitliche `(bool, int $form_id)`-
  Signatur): `creationell_captcha_wpforms_autoinject`,
  `creationell_captcha_wc_checkout_autoinject`,
  `creationell_captcha_wc_login_autoinject`,
  `creationell_captcha_wc_registration_autoinject`,
  `creationell_captcha_wc_lost_password_autoinject`. Bei `false` wird das
  Auto-Inject übersprungen; die Verifikation bleibt aktiv.
- WP-CLI: sechs neue Feature-Schlüssel für `wp creacaptcha enable|disable`
  — `wpforms`, `woocommerce`, `wc-checkout`, `wc-login`, `wc-registration`
  und `wc-lost-password`.
- Bypass-Kette und Kill-Switch wirken wie bei den bestehenden
  Integrationen: jeder Verify-Pfad ruft `creationell_captcha_request_bypassed()`
  und respektiert `CREATIONELL_CAPTCHA_DISABLE`.

### 0.22.0

- Widget-Bugfix: Der ALTCHA-`<altcha-widget>`-Custom-Element-Tag erkennt
  nur 9 spezifische HTML-Attribute (`auto`, `challenge`, `configuration`,
  `display`, `language`, `name`, `theme`, `type`, `workers`) — alle anderen
  Props (Verify-URL, Floating-Anchor/Placement/Offset, Code-Challenge-
  Display, Hide-Footer/Logo, Strings-Override) müssen als JSON-Blob über
  das `configuration`-Attribut übergeben werden. Bisher hat das Plugin
  diese Settings als Einzelattribute emittiert, die das Widget
  stillschweigend ignoriert hat. Sichtbare Folgen: Floating-Anchor griff
  nicht, ALTCHA-Footer/Logo blieben sichtbar, Code-Challenge-Modal-Modi
  (overlay/bottomsheet) wurden ignoriert, eigene Übersetzungen waren
  wirkungslos. Mit v0.22.0 wirken alle Modul-14-Settings korrekt — das
  ist eine Verhaltensänderung, falls jemand diese Felder auf Nicht-
  Default gesetzt hatte.
- Bild-Code-Challenge: Zweite Captcha-Stufe nach der Proof-of-Work-Verifikation
  — ein vom Server ausgestelltes PNG mit einem 4–8-stelligen Code, den der
  User abtippen muss. Self-hosted, kein externer Dienst, kein ALTCHA Sentinel.
- Neue Section „Bild-Code-Challenge" im Captcha-Tab mit Master-Toggle und
  drei unabhängigen Trigger-Bedingungen: Under-Attack-Modus, Rate-Limit-
  Schwellwert (konfigurierbar 50–95 %) sowie eine eigene Watch-Liste von
  IPs/CIDRs. Mehrere Trigger gleichzeitig sind OR-verknüpft.
- Code-Optionen: Länge 4–8, Zeichensatz (nur Ziffern / alphanumerisch /
  alphanumerisch ohne Verwechsler), Token-Gültigkeit 60–900 Sekunden.
- Zwei neue REST-Endpoints: `GET /wp-json/creationell-captcha/v1/code-image`
  (PNG-Bild) und `POST /wp-json/creationell-captcha/v1/code-verify`
  (Code-Prüfung, liefert eine serverseitig gelöste ALTCHA-Payload, die durch
  den bestehenden Verifizierungspfad geht). Tokens sind opake Server-
  Identifier (32 Hex), Code lebt nur in einem WP-Transient — kein
  Client-side-Leak des erwarteten Codes.
- Trigger „Immer": Vierter Trigger-Toggle in der Code-Challenge-Section,
  damit die Code-Challenge unabhängig von Under-Attack / Rate-Limit-
  Schwelle / Watch-Liste bei jedem Captcha-Request ausgespielt wird —
  sinnvoll fürs lokale Testen oder pauschal erhöhte Sicherheit. Default
  aus.
- Under-Attack-Schutz: Code-Challenge wird auf dem Under-Attack-Inter-
  stitial unterdrückt (das Interstitial-Widget ist invisible — ein Code-
  Modal könnte nicht angezeigt werden). Das Interstitial hängt einen
  HMAC-signierten Kontext-Token an die challenge-URL, der nur server-
  seitig signierbar ist; ein Angreifer kann die Suppression nicht selbst
  triggern.
- Das `<altcha-widget>` bekommt verifyUrl (sowie alle anderen Modul-14-
  Settings) via das `configuration`-JSON-Attribut, damit es vom Widget
  überhaupt gelesen wird.
- Bild-Rendering via PHP-GD mit vendorierter DejaVuSans-Bold-TTF unter
  `assets/fonts/captcha.ttf` und naiver Anti-OCR-Verzerrung (rotierte
  Zeichen, Querlinien, Rauschen). Wenn die TTF-Datei fehlt, fällt der
  Renderer auf den GD-Bitmap-Font 5 zurück.
- WP-CLI: `wp creacaptcha status` zeigt eine neue Zeile „Code-Challenge"
  mit dem effektiven Zustand (`an` / `aus` / `inaktiv (kein GD)`).
- Bypass-Schutz: `Engine::verify()` lehnt jeden Payload ab, in dem
  `parameters.data.ccode` gesetzt ist — verhindert, dass ein Angreifer den
  ursprünglichen Code-Challenge-Payload direkt am Form-Submit vorbei
  einreicht. Frische Payloads aus `Engine::issue_signed_payload()` haben
  kein `data.ccode` und passieren den Filter.
- Wenn die PHP-GD-Extension fehlt, deaktiviert sich das Feature
  stillschweigend, der bestehende PoW-Flow bleibt unangetastet, und in der
  Settings-Section erscheint eine Warn-Notice.

### 0.21.0

- Widget: Vendoriert jetzt das ALTCHA-Basis-Stylesheet (`dist/external/altcha.css`)
  und die sieben Theme-CSS-Files (`dist/themes/*.min.css`). Ohne diese fehlten
  alle Display-Modus-Positionierungen (floating/overlay/bar) komplett, und
  das Theme-Attribut hatte keinen sichtbaren Effekt.
- Widget: `widget_display`-Option `bottomsheet` entfernt — der Wert war kein
  gültiger ALTCHA-`display`-Modus (nur Inline-Fallback auf standard). Stattdessen
  neues Setting `widget_code_challenge_display` (standard/overlay/bottomsheet)
  für die ALTCHA-Code-Challenge-Modal, wo `bottomsheet` tatsächlich hingehört.
- Widget: Drei neue Settings für den schwebenden Modus:
  `widget_floating_anchor` (CSS-Selektor, leer = erster Submit-Button),
  `widget_floating_placement` (auto/top/bottom),
  `widget_floating_offset` (px, 0-200). Ohne Anchor bleibt das schwebende
  Widget off-screen — Help-Text macht das jetzt klar.
- Update-Procedure für das Widget-Asset auf einen abgesicherten npm-Bezug
  umgestellt (Schutz vor kompromittierten npm-Paketen).
- Architektur: Neuer Field-Type `text` (single-line input) für CSS-Selektor-
  und ähnliche String-Settings.

### 0.20.0

- Widget: Acht neue Customization-Settings unter „Captcha → Widget-Erscheinungsbild".
  Display-Modus (standard, floating, overlay, bar, invisible, bottomsheet),
  Interaktions-Typ (checkbox/switch/native), automatische Auslösung
  (none/onload/onsubmit), eines der acht ALTCHA-v3-Themes, optionales
  Ausblenden des ALTCHA-Brandings, Akzentfarbe per Color-Picker, eigenes
  CSS und JSON-Override für die Widget-Texte.
- Widget: Das alte zusammengesetzte `widget_mode`-Setting (visible/auto/overlay)
  entfällt; ein Upgrade-Hook migriert beim ersten Admin-Aufruf automatisch
  auf die neuen Keys (`visible` → standard+none, `auto` → invisible+onload,
  `overlay` → floating+onsubmit).
- Widget: Der overlay-Modus aus Modul 11a wird jetzt korrekt mit der v3-
  Syntax `display="floating"` ausgespielt (vorher veraltetes `floating="auto"`).
- Widget: Inline-CSS-Variable `--creationell-captcha-primary` überschreibt
  die ALTCHA-Standard-Akzentfarbe, wenn `widget_primary_color` gesetzt ist.
  Eigenes CSS wird direkt danach ausgegeben und kann beliebig überschreiben.
- WP-CLI: `wp creacaptcha status` zeigt eine neue Zeile „Widget-Anzeige" mit
  dem aktiven Display-Modus.
- Architektur: Zwei neue Field-Typen `color` und `textblock` ergänzen das
  Settings-Framework. `textblock` speichert mehrzeiligen Text ohne die
  Line-Listen-Semantik des bisherigen `textarea`-Typs.

### 0.19.0

- WP-CLI: Fünf neue Listen-Subbefehle für die seit v0.13.0 hinzugekommenen
  Listen-Settings — `wp creacaptcha trusted-proxies|bypass-ua|bypass-cookies|actions|inject-paths`,
  jeweils mit `add|remove|list|clear`. Damit sind alle Listen über
  dedizierte Befehle pflegbar, ohne den Umweg über `settings set`.
- WP-CLI: Neue Subcommand-Gruppe `wp creacaptcha cloudflare` mit
  `refresh`/`clear`/`status`. Der alte Top-Level-Befehl
  `wp creacaptcha refresh-cloudflare-ips` bleibt als Deprecation-Alias
  erhalten (Entfernung frühestens v1.0.0).
- WP-CLI: Neuer Diagnose-Befehl `wp creacaptcha test-bypass`, simuliert
  die Bypass-Auswertung mit `--ip`/`--ua`/`--cookie`-Flags. Exit 0 bei
  Bypass, Exit 1 sonst.
- WP-CLI: Neuer Diagnose-Befehl `wp creacaptcha doctor` mit 9
  Pflicht-Checks (Vendored Library, HMAC-Secrets, Event-Log-Tabelle,
  Cloudflare-Refresh-Cron, Kill-Switch, Captcha-Plugin-Konflikte,
  PHP-Version, Cloudflare-Cache-Alter, Settings-Defaults). Erweiterbar
  über den Filter `creationell_captcha_doctor_checks`.
- WP-CLI: `wp creacaptcha status` listet jetzt auch die fünf neuen
  Listen mit Eintragszählern.
- Werkzeuge-Seite: Neuer fünfter Block „Cloudflare-IP-Cache" mit
  Status (gecachte v4/v6-Ranges, letzter Refresh, nächster Cron-Run,
  Quelle) und zwei Buttons („Jetzt aktualisieren", „Cache leeren").
  Beide Buttons rufen exakt die gleichen Helfer wie die CLI.
- Refactor: Die feldspezifische Validierung für Action-Patterns und
  Bypass-Cookies wurde aus `creationell_captcha_sanitize_settings()` in
  zwei wiederverwendbare Helfer extrahiert — Charset-Änderungen sind
  jetzt an einer Stelle gepflegt. Außerdem wurde `request_bypassed()`
  in eine reine `evaluate_bypass(?ip, ?ua, cookies)` plus dünnen
  Globals-Wrapper aufgeteilt; alle bestehenden Aufrufer bleiben
  unverändert.

### 0.18.0

- Interceptor: Drei neue Mechaniken. Die Pfad-Liste (`Geschützte Pfade`)
  unterstützt jetzt `!`-Präfix für Ausschluss-Muster (Allow-Liste mit
  Ausnahmen), z. B. `/forms/*` zusammen mit `!/forms/whitelisted`. Eine
  neue Liste `Geschützte Aktionen` schützt WordPress-Action-Endpoints
  (das `$_POST[action]`- oder `$_GET[action]`-Feld auf admin-post.php /
  admin-ajax.php) — selbst wenn diese sonst durch den
  `is_admin()`-Bypass ausgenommen wären. Eine neue Liste `Inject-Pfade`
  injiziert die Sicherheitsabfrage automatisch vor jedem `</form>` der
  passenden Seiten — nützlich für Theme- oder Drittanbieter-Formulare,
  die sich nicht direkt modifizieren lassen (idempotent: Formulare mit
  bereits eingebautem Widget werden übersprungen).

### 0.17.0

- Logging-Granularität: Sechs neue Backend-Checkboxes (`Erfolgreiche
  Verifikationen loggen`, `Fehlgeschlagene Verifikationen loggen`,
  `Firewall-Blocks loggen`, `Rate-Limit-Blocks loggen`,
  `Under-Attack-Abfragen loggen`, `Ausgestellte Challenges loggen`)
  steuern, welche Ereignistypen in den Detail-Event-Log geschrieben werden.
  Aggregierte Tages- und Stundenzähler erfassen alle Typen unabhängig
  davon. Per-Default sind die ersten fünf an, `Ausgestellte Challenges
  loggen` ist aus (hochvolumig).
- Neuer Ereignistyp `challenge` — wird bei jedem REST-Aufruf der
  Challenge-Route gefeuert. Im Statistik-Dashboard erscheint die neue
  Kachel/Spalte „Challenges ausgestellt" automatisch.
- Request-Body-Fingerabdruck: Optionaler neuer Schalter
  `Request-Body-Fingerabdruck speichern`. Wenn aktiv, wird pro
  Event-Log-Zeile eine JSON-Map aus Feldnamen und Wertlängen mit
  abgelegt — ohne die Werte selbst. Hilft bei der Angriffsmuster-Analyse,
  ohne PII zu speichern.
- IP-Anonymisierung: Optionaler neuer Schalter `IP-Adressen anonymisieren`
  trunkiert IPv4-Adressen auf das letzte Oktett und IPv6 auf die letzten
  80 Bit, bevor sie in den Event-Log geschrieben werden — DSGVO-konform.

### 0.16.0

- Bypass: Neue Backend-Sektion „Bypass" im Firewall-Tab mit drei
  Eintragsarten, die jeweils Firewall, Rate-Limiter, Captcha und
  Under-Attack-Modus gleichermaßen umgehen — die bisherige
  IP-Erlaubnisliste (jetzt global), eine User-Agent-Wildcard-Liste und
  eine Cookie-Bypass-Liste im Format „name=wert". Bypass-Treffer auf
  Formular-Ebene erscheinen im Event-Log als `verified`-Eintrag mit
  passendem Grund (IP-Allowlist / UA-Bypass / Cookie-Bypass).
- Widget: Dritter Anzeigemodus „Schwebendes Overlay" — die Sicherheits-
  abfrage erscheint als kleines Pop-up über dem Submit-Button und löst
  beim Submit automatisch.

### 0.15.0

- Firewall/IP-Erkennung: Der weitergeleitete Header (X-Forwarded-For,
  X-Real-IP, CF-Connecting-IP, True-Client-IP) wird nur noch dann beachtet,
  wenn die direkte Verbindung aus einem vertrauenswürdigen Hop kommt. Neue
  Sektion „Proxy & IP-Ermittlung" im Firewall-Tab mit Textarea für
  vertrauenswürdige Proxies, Toggles für Private-Netze und Cloudflare und
  optionalem täglichem Cron-Refresh der CF-Ranges. Cloudflare-Snapshot wird
  mitgeliefert. Die Trust-Liste lässt sich zusätzlich über die
  wp-config-Konstante `CREATIONELL_CAPTCHA_TRUSTED_PROXIES` ergänzen. Bei aktivem
  Proxy-Modus ohne konfigurierte Trust-Quelle erscheint im Backend ein
  Hinweis. Neuer WP-CLI-Befehl `wp creacaptcha refresh-cloudflare-ips`.

### 0.14.0

- Statistik: Die Statistik-Seite hat einen „↻ Aktualisieren"-Button. Der
  „Ereignisse"-Tab erfasst je Ereignis zusätzlich Plugin/Integration, Aktion,
  Formular-ID, Auslöser-Grund, User-Agent, Referrer, Benutzer-ID und die
  eingereichten Verifizierungsdaten, zeigt eine erweiterte Spaltenauswahl und
  öffnet pro Zeile ein Detail-Fenster mit allen erfassten Feldern. Der
  CSV-Export enthält die neuen Felder.

### 0.13.0

- WP-CLI: neue Befehlsgruppe `wp creacaptcha …` für Status, Diagnose, Statistik,
  Einstellungen (lesen/setzen/exportieren/importieren/zurücksetzen),
  Modul-Aktivierung, Pflege der IP- und User-Agent-Listen, Verwaltung des
  Event-Logs und eine Reparatur-Routine.
- Backend: neue Seite **CreaCaptcha → Werkzeuge** zum Exportieren und
  Importieren der Einstellungen, für einen vollständigen Reset auf
  Werkseinstellungen sowie zum Laden der Standardwerte unter Beibehaltung der
  gepflegten Listen.

### 0.12.0

- Statistik: Der „Ereignisse"-Tab hat jetzt eine Filter-Leiste — Freitextsuche
  über IP-Adresse und Pfad, Filter nach Ereignistyp und ein Von/Bis-Datumsbereich
  —, blättert seitenweise durch alle aufgezeichneten Ereignisse und bietet einen
  CSV-Export der jeweils gefilterten Ereignismenge zur weiteren Analyse.

### 0.11.0

- Statistik: Die Statistik-Seite ist jetzt ein Dashboard mit drei Tabs
  (Übersicht, Verlauf, Ereignisse). Der „Übersicht"-Tab zeigt KPI-Kacheln für
  den 24-Stunden-Blick und eine Vergleichstabelle über vier Zeitfenster
  (24 Stunden, 7 Tage, 30 Tage, 90 Tage); ein neuer stündlicher Zähler liefert
  die Daten für das 24-Stunden-Fenster.

### 0.10.0

- Backend: Die Einstellungsseite ist jetzt in sechs thematische Tabs gegliedert
  (Captcha, Formulare, Firewall, Under-Attack, E-Mail-Schutz, Analytics) statt
  einer langen Liste — übersichtlicher, mit weiterhin einem gemeinsamen
  „Änderungen speichern" für alle Tabs.

### 0.9.0

- E-Mail-Schutz: zusätzlicher Ganzseiten-Buffer-Modus, der das gesamte
  Seiten-HTML verarbeitet und damit auch theme-hart-kodierte `mailto:`-Links und
  Adressen (z. B. in Footer-Templates) verschleiert; der Modus ist unter
  „Einstellungen → CreaCaptcha → E-Mail-Schutz" wählbar.

### 0.8.0

- E-Mail-Obfuskation: `mailto:`-Links und Klartext-E-Mail-Adressen in Inhalten,
  Auszügen, Text-Widgets und Kommentaren werden im Seitenquelltext verschleiert
  und per JavaScript erst im Browser wiederhergestellt; ohne JavaScript erscheint
  ein neutraler Platzhalter.

### 0.7.0

- Analytics & Event-Logging: datenschutzfreundliche aggregierte Tageszähler je
  Ereignistyp und ein Statistik-Dashboard; optional ein detaillierter
  Event-Log (eigene Tabelle, IP-Adressen) mit konfigurierbarer Aufbewahrung.

### 0.6.0

- Under-Attack-Modus: ein einschaltbarer Notfall-Modus, der jeden anonymen
  Besucher per Interstitial-Proof-of-Work-Abfrage prüft, bevor er die Website
  erreicht; ein zeitlich begrenzter, signierter Pass-Cookie lässt geprüfte
  Besucher danach frei surfen.

### 0.5.0

- Firewall & Rate-Limiting: IP-Blockliste/-Erlaubnisliste (inkl. CIDR-Bereiche),
  User-Agent-Blockliste und ein per-IP-Rate-Limiter mit wählbarem Wirkungsbereich.
  Beide laufen als frühe Request-Guards, mit Proxy-Modus für die Client-IP-Ermittlung.

### 0.4.0

- Integrationen für Contact Form 7 und Forminator: automatischer
  Proof-of-Work-Schutz für die Formulare beider Plugins, mit
  `[creationell_captcha]`-Platzhalter zur Positionierung und je einem
  Einstellungs-Schalter.

### 0.3.0

- Interceptor-Modul: generischer serverseitiger Request-Schutz für eigene
  Formular-Pfade (`*`-Wildcards, fail-closed), Shortcode `[creationell_captcha]`
  und Template-Tag `creationell_captcha_widget()` zum Einbau des Widgets in
  beliebige Formulare.

### 0.2.0

- Captcha-Mechanik: Proof-of-Work-Sicherheitsabfrage (PBKDF2/SHA-256 oder
  Argon2id), Challenge-REST-Endpoint, gebündelte ALTCHA-Widget-Web-Component,
  Replay-Schutz und Schutz der vier WordPress-Kernformulare.

### 0.1.0

- Erstes Grundgerüst: Plugin-Bootstrap, Settings-API-Seite, gebündelte
  ALTCHA-Bibliothek (Composer + Strauss) und Self-Hosted-GitHub-Updater.
