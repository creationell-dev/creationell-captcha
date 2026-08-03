<?php
/**
 * Fail-safe-Migration: findet gefährliche Bestandskonfiguration und MELDET sie.
 *
 * Die Eingabeprüfung dieser Version weist vier Werte ab, die frühere Versionen
 * durchgelassen haben: die Präfixlänge 0 in einer IP-Liste (`0.0.0.0/0`,
 * `::/0` — AF-5/CLI-1), einen `bypass_cookies`-Eintrag ohne Wert (BK-14) und
 * ein Catch-all-Muster in `bypass_ua_allow` (BK-9). Dazu kommen zwei Klassen,
 * die keine Eingabeprüfung abweist, weil sie syntaktisch einwandfrei sind: ein
 * IP-Bereich in IPv4-mapped Schreibweise (`::ffff:0:0/96`), der seit der
 * Kanonisierung aus Befund I2 nichts mehr trifft, und ein UA-Muster wie
 * Stern-Schrägstrich-Stern, das jeden realistischen Kennzeichner trifft, ohne
 * ein blosses Sternchen zu sein (B-M2). Das gilt aber alles nur für NEUE
 * Eingaben. Was bereits in der Option steht, bleibt unangetastet: eine
 * laufende Installation still umzuschreiben, während der Betreiber nichts
 * davon weiß, wäre die schlechtere Variante — der Bypass, den er morgen
 * vermisst, kann der sein, über den sein Monitoring läuft.
 *
 * Diese Datei ist der Gegenpart dazu. Sie SCHREIBT NICHTS. Sie liest die
 * Einstellungen, benennt jeden Fund mit Liste, Eintrag und Konsequenz und
 * zeigt ihn über beide Kanäle: als Admin-Hinweis im Backend und als Zeile in
 * `wp creacaptcha doctor`.
 *
 * Bewusst NICHT gemeldet wird `0.0.0.0/0` in der IP-BLOCKliste: dort heißt der
 * Eintrag korrekt „alles sperren" und ist zusammen mit der Erlaubnisliste ein
 * legitimes Whitelist-Only-Muster. Eine Meldung, die auch das anmeckert,
 * erzieht den Betreiber dazu, Meldungen zu überlesen.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/** User-Meta-Schlüssel, unter dem ein Benutzer den Hinweis wegklickt. */
const CREATIONELL_CAPTCHA_HARDENING_DISMISS_META = 'creationell_captcha_hardening_dismissed';

/** Query-Parameter des Ausblenden-Links. */
const CREATIONELL_CAPTCHA_HARDENING_DISMISS_ARG = 'creationell_captcha_hardening_dismiss';

/**
 * Ermittelt, WELCHE Adressfamilie ein gespeicherter Listeneintrag vollständig
 * abdeckt und die Liste für diese Familie damit als Auswahl aufhebt.
 *
 * Zwei Fragen, zwei vorhandene Wurzeln — hier entsteht bewusst keine dritte
 * IP-Prüfung (die Doppelung eines Validators war in diesem Audit schon zweimal
 * ein Befund, AF-5 und CLI-1):
 *
 *   1. `creationell_captcha_is_valid_ip_or_cidr()` — was die Eingabeprüfung
 *      dieser Version akzeptiert, ist per Definition kein Altlastwert. Das hält
 *      Falschmeldungen auf regulären Einträgen von vornherein fern, auch auf
 *      `0.0.0.0/1` + `128.0.0.0/1`, mit denen ein Betreiber den gesamten
 *      Adressraum weiterhin abdecken darf — wenn er es ausspricht.
 *   2. `creationell_captcha_ip_in_cidr()` — derselbe Matcher, den Firewall,
 *      Proxy-Vertrauen und Watch-Liste zur Laufzeit benutzen. Trifft er die
 *      erste UND die letzte Adresse einer Familie, deckt der Eintrag alles
 *      dazwischen ebenfalls ab (CIDR-Präfixe sind zusammenhängend).
 *
 * Deshalb erkennt die Prüfung auch Schreibweisen, die ein Textvergleich gegen
 * „0.0.0.0/0" verfehlt hätte — `10.0.0.0/0` und `0.0.0.0/00` gehören dazu.
 *
 * Zurückgegeben wird die Familie und nicht nur ein Ja/Nein, weil die Meldung sie
 * braucht: `0.0.0.0/0` deckt AUSSCHLIESSLICH IPv4 ab, `::/0` ausschließlich
 * IPv6. `creationell_captcha_ip_in_cidr()` verlangt gleiche Binärlänge von
 * Adresse und Netz, ein Eintrag kann also nie beide Familien treffen — und was
 * er nicht trifft, läuft an der Liste vorbei. Bei den vertrauenswürdigen
 * Proxies ist genau das der gefährlichere Teil des Fundes (siehe die Meldung
 * unten), deshalb darf die Familie hier nicht verlorengehen.
 *
 * @param string $entry Eintrag aus der gespeicherten Liste (bereits getrimmt).
 * @return string 'IPv4', 'IPv6' oder '' — Letzteres heißt: deckt keine Familie
 *                vollständig ab, also kein Fund.
 */
function creationell_captcha_hardening_covered_family( string $entry ): string {
    if ( '' === $entry || creationell_captcha_is_valid_ip_or_cidr( $entry ) ) {
        return '';
    }

    $families = [
        'IPv4' => [ '0.0.0.0', '255.255.255.255' ],
        'IPv6' => [ '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ],
    ];

    foreach ( $families as $family => $probes ) {
        $covers_family = true;
        foreach ( $probes as $probe ) {
            if ( ! creationell_captcha_ip_in_cidr( $probe, $entry ) ) {
                $covers_family = false;
                break;
            }
        }
        if ( $covers_family ) {
            return $family;
        }
    }

    return '';
}

/**
 * Erkennt einen CIDR-Bereich, der in IPv4-mapped Schreibweise notiert ist
 * (`::ffff:0:0/96`, `::ffff:203.0.113.0/120`), und liefert seine gewöhnliche
 * IPv4-Schreibweise zurück.
 *
 * WARUM DAS EINE EIGENE PRÜFUNG IST
 * ---------------------------------
 * Die Prüfung eine Etage höher (creationell_captcha_hardening_covered_family())
 * kann diese Klasse konstruktionsbedingt nicht finden. Sie steigt bei jedem
 * Eintrag aus, den `creationell_captcha_is_valid_ip_or_cidr()` annimmt — und
 * `::ffff:0:0/96` ist eine syntaktisch einwandfreie IPv6-Notation mit
 * Präfixlänge 96, wird also angenommen. Auch die beiden Familien-Sonden greifen
 * nicht: `0.0.0.0` ist vier Byte lang, der Eintrag sechzehn, und
 * `creationell_captcha_ip_in_cidr()` verlangt zu Recht gleiche Binärlänge.
 *
 * WAS DER EINTRAG BEDEUTET — GEMESSEN, NICHT VERMUTET
 * ---------------------------------------------------
 * Bis 1.0.2 hat niemand die Client-Adresse vereinheitlicht. Auf einem Server,
 * dessen PHP die Gegenstelle in mapped Schreibweise sieht (nginx mit
 * `ipv6only=off`, Apache auf einem IPv6-Socket, viele Container-Setups), kam
 * `REMOTE_ADDR` dort als `::ffff:203.0.113.7` an — sechzehn Byte, dieselbe
 * Familie wie der Eintrag. `::ffff:0:0/96` traf damit JEDE IPv4-Adresse. In
 * `firewall_trusted_proxies` hiess das: jede Gegenstelle gilt als eigener
 * Proxy, der weitergeleitete Header wird ungeprüft übernommen. Die `/0`-Regel
 * der Eingabeprüfung fängt diese Schreibweise nicht.
 *
 * Seit Modul 27 (Befund I2) kanonisiert `creationell_captcha_normalize_ip()`
 * die Client-Adresse auf die gewöhnliche IPv4-Schreibweise — vier Byte. Der
 * RANGE bleibt bewusst stehen wie geschrieben, weil ein automatisch
 * umgeschriebenes Vertrauens-Netz die eine Richtung wäre, die hier nie
 * passieren darf. Folge: der Eintrag trifft heute NICHTS mehr. Gemessen:
 *
 *     ip_in_list( '203.0.113.7',        [ '::ffff:0:0/96' ] )  → false
 *     ip_in_list( '::ffff:203.0.113.7', [ '::ffff:0:0/96' ] )  → false
 *
 * Er ist damit kein offenes Tor mehr, sondern eine Zeile, die für den Betreiber
 * wie eine wirksame Regel aussieht und keine ist — genau die Klasse `unwirksam`,
 * für die dieses Feld existiert. Bei einer Blockliste ist das ein still
 * verlorener Schutz, bei den Erlaubnis-/Vertrauenslisten eine still verlorene
 * Ausnahme. Beides gehört gemeldet.
 *
 * Blanke Einzeladressen in mapped Schreibweise sind NICHT betroffen:
 * `creationell_captcha_ip_in_list()` kanonisiert dort beide Seiten, ein
 * gespeichertes `::ffff:203.0.113.7` trifft also weiterhin. Deshalb verlangt
 * diese Funktion einen Schrägstrich.
 *
 * Präfixe unter 96 gelten nicht als mapped Bereich: dort tragen die zwölf
 * Bytes des Mapped-Präfixes die Entscheidung nicht mehr vollständig, der
 * Eintrag ist dann ein gewöhnlicher IPv6-Bereich (und `::ffff:0:0/0` fängt
 * bereits die Familien-Prüfung oben ab).
 *
 * @param string $entry Eintrag aus der gespeicherten Liste (bereits getrimmt).
 * @return string Gewöhnliche IPv4-Schreibweise des Bereichs, oder '' wenn der
 *                Eintrag kein IPv4-Bereich in mapped Notation ist.
 */
function creationell_captcha_hardening_mapped_ipv4_cidr( string $entry ): string {
    if ( ! str_contains( $entry, '/' ) ) {
        return '';
    }

    [ $subnet, $bits ] = array_pad( explode( '/', $entry, 2 ), 2, '' );

    if ( ! ctype_digit( $bits ) ) {
        return '';
    }
    $bits = (int) $bits;
    if ( $bits < 96 || $bits > 128 ) {
        return '';
    }

    $bin = @inet_pton( $subnet );
    if ( false === $bin || 16 !== strlen( $bin ) ) {
        return '';
    }

    // RFC 4291 §2.5.5.2 — 80 Nullbits, 16 Einsbits, danach die IPv4-Adresse.
    if ( "\0\0\0\0\0\0\0\0\0\0\xff\xff" !== substr( $bin, 0, 12 ) ) {
        return '';
    }

    $plain = @inet_ntop( substr( $bin, 12 ) );
    if ( ! is_string( $plain ) ) {
        return '';
    }

    return $plain . '/' . ( $bits - 96 );
}

/**
 * Prüft, ob ein `bypass_ua_allow`-Muster jeden Browser-Kennzeichner trifft.
 *
 * Entschieden wird das vom Produktions-Matcher selbst, nicht von einer zweiten
 * Regel: `creationell_captcha_wildcard_match()` kennt den Schalter
 * `$allow_catch_all`, und die Bypass-Auswertung ruft ihn mit `false` auf
 * (BK-9). Ein Muster, das MIT erlaubtem Catch-all trifft und OHNE nicht mehr,
 * ist genau eines, das der Schalter aussortiert — was immer die Regel dahinter
 * gerade ist. Ein Muster wie `*pingdom*` trifft in beiden Aufrufen gleich und
 * fällt damit nicht auf.
 *
 * Ein Catch-all trifft jeden nicht-leeren Kennzeichner, deshalb genügt eine
 * Probe.
 *
 * GRENZE DIESER PRÜFUNG (Befund B-M2)
 * -----------------------------------
 * Das Kriterium findet definitionsgemäss nur die Menge, die der Laufzeit-Guard
 * bereits aussortiert — also Muster mit `wirkung: unwirksam`. Ein Muster, das
 * jeden realen Kennzeichner trifft, ohne ein blosses Sternchen zu sein, kommt
 * durch beide Aufrufe gleich zurück und fällt hier NICHT auf. Das genannte
 * Gegenbeispiel `*pingdom*` ist harmlos; Stern-Schraegstrich-Stern ist es
 * nicht — dieses Muster trifft jeden
 * User-Agent mit einem Schrägstrich, also praktisch jeden. Diese Klasse deckt
 * creationell_captcha_hardening_matches_every_user_agent() ab.
 *
 * Nebenwirkung: bei aktivem `CREATIONELL_CAPTCHA_DEBUG` schreibt der Matcher
 * eine Zeile ins Log, wenn er ein Catch-all aussortiert — durch diese Prüfung
 * also auch dann, wenn gerade keine echte Anfrage ausgewertet wird. Die Aussage
 * der Zeile stimmt trotzdem: das Muster ist wirkungslos.
 *
 * @param string $pattern Muster aus der gespeicherten Liste.
 */
function creationell_captcha_hardening_is_catch_all_pattern( string $pattern ): bool {
    $probe = 'creacaptcha-hardening-probe';

    return creationell_captcha_wildcard_match( $probe, [ $pattern ], false, true )
        && ! creationell_captcha_wildcard_match( $probe, [ $pattern ], false, false );
}

/**
 * Prüft, ob ein `bypass_ua_allow`-Muster jeden realistischen User-Agent trifft,
 * ohne vom Catch-all-Guard aussortiert zu werden (Befund B-M2).
 *
 * Der Guard in `creationell_captcha_wildcard_match()` verwirft ein Muster nur,
 * wenn nach `trim( $pattern, '*' )` nichts übrig bleibt — `*` und `**` also,
 * Stern-Schraegstrich-Stern nicht. Und dieses Muster trifft jeden
 * User-Agent, der einen Schrägstrich
 * enthält: `Mozilla/5.0 …`, `curl/8.5.0`, `python-requests/2.31.0`. Wer diese
 * Zeile einträgt, hat den gesamten Schutz für jeden Besucher abgeschaltet und
 * bekommt heute keine Meldung.
 *
 * DAS KRITERIUM IST BEWUSST „ALLE SONDEN" UND NICHT „EINE SONDE"
 * --------------------------------------------------------------
 * Gemeldet wird nur, was JEDE der Sonden trifft — also ein Muster, das keinen
 * realistischen Kennzeichner mehr auslässt. Ein Existenzquantor hätte
 * `Mozilla*` (trifft Browser, nicht `curl`) und `*Chrome*` mitgemeldet; das
 * sind enge Auswahlen, keine Totalabschaltungen, und eine Meldung darüber wäre
 * genau die Falschmeldung, die den Betreiber zum Wegklicken erzieht. Die
 * Sondenmenge deckt deshalb absichtlich verschiedene Bauformen ab: Browser mit
 * Klammerausdruck, blankes Werkzeug ohne Leerzeichen, Bibliothek, Bot mit URL.
 *
 * Anders als beim blossen Sternchen greift hier KEIN Laufzeit-Guard: das Muster
 * wird ausgewertet und trifft. Der Fund ist deshalb `aktiv`, nicht `unwirksam`.
 *
 * @param string $pattern Muster aus der gespeicherten Liste.
 */
function creationell_captcha_hardening_matches_every_user_agent( string $pattern ): bool {
    $probes = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'curl/8.5.0',
        'python-requests/2.31.0',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Wget/1.21.4',
    ];

    foreach ( $probes as $probe ) {
        // Mit der Polarität der Laufzeit-Auswertung (BK-9): `false, false`.
        // Ein Muster, das der Guard ohnehin verwirft, kann so gar nicht erst
        // in diese Meldung geraten — es gehört in die Catch-all-Meldung.
        if ( ! creationell_captcha_wildcard_match( $probe, [ $pattern ], false, false ) ) {
            return false;
        }
    }

    return true;
}

/**
 * Durchsucht einen Satz Einstellungen nach gefährlicher Bestandskonfiguration.
 *
 * Keine Option wird gelesen, keine geschrieben. Der Aufrufer liefert die
 * Einstellungen; das macht die Erkennung ohne WordPress prüfbar
 * (`tests/test-hardening-migration.php`). Der einzige Blick nach draußen ist
 * `extension_loaded( 'gd' )` — und auch der ist über `$gd_available`
 * abschaltbar, damit der Test nicht davon abhängt, wie der Rechner gebaut ist,
 * auf dem er läuft.
 *
 * Jeder Fund trägt ein Feld `wirkung`. Drei Werte, weil „greift nicht" drei
 * verschiedene Dinge heißen kann und der Betreiber sie auseinanderhalten muss:
 *   - `aktiv`      — der Eintrag greift zur Laufzeit hier und jetzt.
 *   - `unwirksam`  — ein Laufzeit-Guard überspringt ihn seit dieser Version
 *                    dauerhaft (BK-9, BK-14). Kein Schalter holt ihn zurück.
 *                    Er steht trotzdem in der Konfiguration und liest sich für
 *                    den Betreiber wie eine wirksame Ausnahme — deshalb genannt.
 *   - `ruhend`     — der Eintrag greift nur nicht, weil die Funktion, die seine
 *                    Liste liest, gerade ausgeschaltet ist. Er ist scharf, sobald
 *                    sie eingeschaltet wird — eine Tretmine, kein toter Buchstabe.
 *
 * Warum das Feld nicht pauschal `aktiv` sein darf: zwei der drei IP-Listen
 * werden zur Laufzeit hinter einem Schalter gelesen (siehe unten). Auf einer
 * Installation mit den Vorgabewerten (`firewall_behind_proxy` = false,
 * `code_challenge_enabled` = false) bekäme der Betreiber sonst eine rote
 * Fehlermeldung über zwei Optionswerte, die kein Codepfad überhaupt anschaut —
 * und lernt daraus, Meldungen dieses Plugins wegzuklicken.
 *
 * @param array<string, mixed> $settings     Gespeicherte Plugin-Einstellungen.
 * @param bool|null            $gd_available PHP-GD vorhanden? `null` = selbst
 *                                           nachsehen. Nur zum Testen gesetzt —
 *                                           GD ist Teil des Watch-Listen-Gates
 *                                           (siehe creationell_captcha_should_issue_code_challenge()),
 *                                           aber eine Umgebungs- und keine
 *                                           Einstellungsfrage.
 * @return array<int, array{id: string, liste: string, eintrag: string, wirkung: string, tab: string, meldung: string}>
 */
function creationell_captcha_hardening_scan( array $settings, ?bool $gd_available = null ): array {
    $findings     = [];
    $gd_available = null === $gd_available ? extension_loaded( 'gd' ) : $gd_available;

    // --- 1. IP-Listen mit Erlaubnis-/Vertrauens-Charakter --------------------
    // Nur diese drei. Die IP-Blockliste und die User-Agent-Blockliste stehen
    // bewusst NICHT hier: ein Eintrag, der dort alles trifft, sperrt alles —
    // eine Absicht, keine Altlast.
    //
    // `wirksam` beantwortet je Liste: liest der Laufzeitpfad diese Liste in der
    // vorliegenden Konfiguration überhaupt? Die Antwort steht nicht in dieser
    // Datei, sondern an der Leseseite — sie ist hier abgeschrieben und in
    // tests/test-hardening-migration.php Abschnitt 5 gegen den echten Pfad
    // gehalten, damit das Feld `wirkung` eine Messung bleibt und keine
    // Behauptung wird.
    $proxy_modus_an = ! empty( $settings['firewall_behind_proxy'] );
    $watchliste_an  = ! empty( $settings['code_challenge_enabled'] )
        && ! empty( $settings['code_challenge_trigger_watchlist'] )
        && $gd_available;

    // `meldung` ist hier eine Funktion und kein fertiger Satz: Ein Eintrag deckt
    // immer nur EINE Adressfamilie ab (siehe
    // creationell_captcha_hardening_covered_family()), und welche das ist,
    // entscheidet über die Konsequenz. Die Meldung bekommt deshalb die Familie
    // des Eintrags ($familie) und die jeweils andere ($andere) übergeben.
    $ip_lists = [
        'firewall_ip_allow'        => [
            'label'   => __( 'IP-Erlaubnisliste (global)', 'creationell-captcha' ),
            'tab'     => 'firewall',
            // Ohne Gate: creationell_captcha_evaluate_bypass() (helpers.php)
            // prüft diese Liste ohne Vorbedingung, und der Aufrufweg dorthin
            // führt über Firewall, Rate-Limiter, Under-Attack, Interceptor und
            // alle fünf Formular-Integrationen. Es gibt keinen Schalter, der
            // sie stilllegt — ein Eintrag hier wirkt immer.
            'wirksam' => true,
            'meldung' => static fn( string $familie, string $andere ): string => sprintf(
                /* translators: %1$s: Adressfamilie des Eintrags — „IPv4" oder „IPv6". */
                __( 'Dieser Eintrag trifft auf jede %1$s-Adresse zu. Damit ist jeder Besucher, der über %1$s kommt, von Sicherheitsabfrage, Firewall, Rate-Limit und Under-Attack-Modus ausgenommen — für diese Adressen hebt die Erlaubnisliste den gesamten Schutz auf.', 'creationell-captcha' ),
                $familie
            ),
        ],
        'firewall_trusted_proxies' => [
            'label'   => __( 'Vertrauenswürdige Proxies', 'creationell-captcha' ),
            'tab'     => 'firewall',
            // Gate: creationell_captcha_is_trusted_proxy() hat genau einen
            // Aufrufer, creationell_captcha_get_client_ip(), und der steigt bei
            // ausgeschaltetem `firewall_behind_proxy` aus, bevor die Liste
            // überhaupt gelesen wird (helpers.php).
            'wirksam' => $proxy_modus_an,
            // Zwei Folgen, und die zweite ist die schlimmere.
            //
            // (1) Innerhalb der abgedeckten Familie ist es KEIN Spoofing:
            // get_client_ip() läuft die Weiterleitungskette von rechts nach
            // links und nimmt den ersten Sprung, der NICHT vertrauenswürdig
            // ist. Gilt jeder Sprung dieser Familie als vertrauenswürdig,
            // bleibt keiner übrig und die Funktion fällt auf REMOTE_ADDR zurück
            // — alle Besucher tragen dieselbe Adresse, nämlich die des Proxys.
            //
            // (2) Über die Familiengrenze hinweg ist es sehr wohl Spoofing:
            // creationell_captcha_ip_in_cidr() verlangt gleiche Binärlänge, ein
            // IPv6-Sprung ist unter `0.0.0.0/0` also NICHT vertrauenswürdig und
            // gewinnt den Rechts-nach-links-Lauf sofort. Peer 203.0.113.9 und
            // „X-Forwarded-For: 2001:db8::dead, 198.51.100.77" ergeben
            // gemessen 2001:db8::dead — die Absenderadresse wird frei wählbar,
            // und mit ihr fallen Rate-Limit (class-rate-limiter.php, Transient
            // je IP), IP-Sperren und jede IPv6-Zeile der Erlaubnisliste. Mit
            // `::/0` gilt dasselbe spiegelverkehrt. Deshalb nennt die Meldung
            // beide Folgen; die frühere Fassung verneinte Spoofing pauschal.
            'meldung' => static fn( string $familie, string $andere ): string => $proxy_modus_an
                ? sprintf(
                    /* translators: 1: Adressfamilie des Eintrags („IPv4" oder „IPv6"), 2: die jeweils andere Familie. */
                    __( 'Dieser Eintrag stuft jede %1$s-Gegenstelle als Ihren eigenen Proxy ein — das hat zwei Folgen. Erstens zählt für Besucher, die über %1$s kommen, nur noch die Adresse der unmittelbar verbundenen Gegenstelle, hinter einem echten Proxy also für alle dieselbe: Das Rate-Limit wird zu einem gemeinsamen Zähler, IP-Sperren treffen den einzelnen Besucher nicht mehr, und steht diese eine Adresse in der Erlaubnisliste, ist jeder ausgenommen. Zweitens gilt der Eintrag für %2$s NICHT: Wer über %1$s verbunden ist und eine %2$s-Adresse in den Proxy-Header schreibt, wird unter genau dieser selbst gewählten Adresse geführt und kann sie bei jeder Anfrage wechseln — Rate-Limit und IP-Sperren laufen dann ins Leere, und steht eine %2$s-Adresse in der Erlaubnisliste, kann sich jeder als diese ausgeben. Hier gehören nur die Adressen Ihrer eigenen Proxies hinein.', 'creationell-captcha' ),
                    $familie,
                    $andere
                )
                : sprintf(
                    /* translators: 1: Adressfamilie des Eintrags („IPv4" oder „IPv6"), 2: die jeweils andere Familie. */
                    __( 'Dieser Eintrag stuft jede %1$s-Gegenstelle als Ihren eigenen Proxy ein. Er wirkt zurzeit nicht, weil der Proxy-Modus ausgeschaltet ist — sobald Sie ihn einschalten, zählt für Besucher über %1$s nur noch die Adresse der unmittelbar verbundenen Gegenstelle (ein gemeinsamer Rate-Limit-Zähler für alle), und wer über %1$s verbunden ist, kann sich mit einer selbst gewählten %2$s-Adresse im Proxy-Header eine beliebige Absenderadresse geben. Zeile jetzt entfernen oder durch die Adressen Ihrer eigenen Proxies ersetzen.', 'creationell-captcha' ),
                    $familie,
                    $andere
                ),
        ],
        'code_challenge_watchlist' => [
            'label'   => __( 'Watch-Liste (Bild-Code)', 'creationell-captcha' ),
            'tab'     => 'captcha',
            // Gate: die Liste wird nur in creationell_captcha_should_issue_code_challenge()
            // gelesen, und zwar hinter `code_challenge_enabled`, vorhandenem
            // PHP-GD und `code_challenge_trigger_watchlist` (code-challenge.php).
            'wirksam' => $watchliste_an,
            'meldung' => static fn( string $familie, string $andere ): string => $watchliste_an
                ? sprintf(
                    /* translators: %1$s: Adressfamilie des Eintrags — „IPv4" oder „IPv6". */
                    __( 'Dieser Eintrag trifft auf jede %1$s-Adresse zu. Damit bekommt jeder Besucher, der über %1$s kommt, zusätzlich die Bild-Eingabe vorgelegt — für diese Adressen wirkt die Liste nicht mehr als Auswahl, sondern schaltet die zweite Stufe pauschal ein.', 'creationell-captcha' ),
                    $familie
                )
                : sprintf(
                    /* translators: %1$s: Adressfamilie des Eintrags — „IPv4" oder „IPv6". */
                    __( 'Dieser Eintrag trifft auf jede %1$s-Adresse zu. Er wirkt zurzeit nicht, weil die Bild-Eingabe über die Watch-Liste gerade nicht aktiv ist — sobald sie es ist, bekommt jeder Besucher über %1$s zusätzlich die Bild-Eingabe vorgelegt statt nur die aufgeführten Adressen. Zeile jetzt entfernen oder auf die Adressen einschränken, die Sie wirklich meinen.', 'creationell-captcha' ),
                    $familie
                ),
        ],
    ];

    foreach ( $ip_lists as $key => $meta ) {
        foreach ( (array) ( $settings[ $key ] ?? [] ) as $raw ) {
            // Getrimmt wie in creationell_captcha_ip_in_list() — sonst würde
            // die Meldung an einem Leerzeichen scheitern, an dem der Matcher
            // zur Laufzeit nicht scheitert.
            $entry   = trim( (string) $raw );
            $familie = creationell_captcha_hardening_covered_family( $entry );
            if ( '' === $familie ) {
                continue;
            }
            $andere = 'IPv4' === $familie ? 'IPv6' : 'IPv4';

            $findings[] = [
                'id'      => $key . '|' . $entry,
                'liste'   => $meta['label'],
                'eintrag' => $entry,
                'wirkung' => $meta['wirksam'] ? 'aktiv' : 'ruhend',
                'tab'     => $meta['tab'],
                'meldung' => ( $meta['meldung'] )( $familie, $andere ),
            ];
        }
    }

    // --- 1b. IP-Bereiche in IPv4-mapped Schreibweise -------------------------
    //
    // Andere Wurzel als Abschnitt 1 und deshalb ein eigener Durchlauf: dort
    // geht es um einen Eintrag, der ZU VIEL trifft, hier um einen, der seit
    // dieser Version GAR NICHTS mehr trifft (siehe
    // creationell_captcha_hardening_mapped_ipv4_cidr()). Und anders als oben
    // gehört die BLOCKliste hier dazu: `0.0.0.0/0` heisst dort bewusst „alles
    // sperren", ein wirkungslos gewordener Bereich dagegen ist auch dort ein
    // still verlorener Schutz — es gibt keine Lesart, in der er gewollt ist.
    //
    // `wirkung` ist durchgehend `unwirksam`: die Kanonisierung der
    // Client-Adresse läuft ohne Vorbedingung, kein Schalter holt den Eintrag
    // zurück. Damit bleibt der Hinweis gelb statt rot — richtig, denn gerade
    // steht nichts offen; offen stand es vor dem Update.
    $mapped_lists = [
        'firewall_ip_allow'        => [
            'label' => __( 'IP-Erlaubnisliste (global)', 'creationell-captcha' ),
            'tab'   => 'firewall',
            'folge' => __( 'Bis zu diesem Update waren die davon erfassten Besucher auf solchen Servern von Sicherheitsabfrage, Firewall, Rate-Limit und Under-Attack-Modus ausgenommen; jetzt ist es niemand mehr.', 'creationell-captcha' ),
        ],
        'firewall_trusted_proxies' => [
            'label' => __( 'Vertrauenswürdige Proxies', 'creationell-captcha' ),
            'tab'   => 'firewall',
            'folge' => __( 'Bis zu diesem Update galt auf solchen Servern jede davon erfasste Gegenstelle als Ihr eigener Proxy — der weitergeleitete Header wurde übernommen, die Absenderadresse war damit frei wählbar. Jetzt gilt keine mehr: der Header wird ignoriert, und alle Besucher hinter diesem Proxy zählen unter dessen Adresse (ein gemeinsamer Rate-Limit-Zähler).', 'creationell-captcha' ),
        ],
        'code_challenge_watchlist' => [
            'label' => __( 'Watch-Liste (Bild-Code)', 'creationell-captcha' ),
            'tab'   => 'captcha',
            'folge' => __( 'Bis zu diesem Update bekamen die davon erfassten Besucher auf solchen Servern zusätzlich die Bild-Eingabe vorgelegt; jetzt bekommt sie über diese Zeile niemand mehr.', 'creationell-captcha' ),
        ],
        'firewall_ip_block'        => [
            'label' => __( 'IP-Blockliste', 'creationell-captcha' ),
            'tab'   => 'firewall',
            'folge' => __( 'Bis zu diesem Update wurden die davon erfassten Adressen auf solchen Servern mit HTTP 403 abgewiesen; jetzt kommen sie durch — die Sperre besteht nur noch auf dem Papier.', 'creationell-captcha' ),
        ],
    ];

    foreach ( $mapped_lists as $key => $meta ) {
        foreach ( (array) ( $settings[ $key ] ?? [] ) as $raw ) {
            if ( ! is_scalar( $raw ) ) {
                continue;
            }
            $entry = trim( (string) $raw );
            $plain = creationell_captcha_hardening_mapped_ipv4_cidr( $entry );
            if ( '' === $plain ) {
                continue;
            }

            $hinweis = sprintf(
                /* translators: %s: der Bereich in gewöhnlicher IPv4-Schreibweise, z. B. „203.0.113.0/24". */
                __( 'In gewöhnlicher Schreibweise lautet der Bereich %s.', 'creationell-captcha' ),
                $plain
            );
            if ( str_ends_with( $plain, '/0' ) ) {
                $hinweis = sprintf(
                    /* translators: %s: der Bereich in gewöhnlicher IPv4-Schreibweise, hier immer mit Präfix 0. */
                    __( 'In gewöhnlicher Schreibweise lautet der Bereich %s — er deckt also den gesamten IPv4-Adressraum ab, und genau diese Zeile nimmt die Eingabeprüfung seit dieser Version nicht mehr an, weil sie die ganze Liste aufhebt.', 'creationell-captcha' ),
                    $plain
                );
            }

            $findings[] = [
                'id'      => $key . '|mapped|' . $entry,
                'liste'   => $meta['label'],
                'eintrag' => $entry,
                'wirkung' => 'unwirksam',
                'tab'     => $meta['tab'],
                'meldung' => __( 'Dieser Bereich ist in IPv4-mapped Schreibweise notiert („::ffff:…"). Seit dieser Version wird die Adresse des Besuchers auf die gewöhnliche IPv4-Schreibweise vereinheitlicht — ein CIDR-Bereich in mapped Notation trifft damit keine Adresse mehr und wirkt nicht.', 'creationell-captcha' )
                    . ' ' . $meta['folge']
                    . ' ' . $hinweis
                    . ' ' . __( 'Zeile entfernen oder durch den gewöhnlich geschriebenen Bereich ersetzen.', 'creationell-captcha' ),
            ];
        }
    }

    // --- 2. Cookie-Bypass ohne Geheimnis (BK-14) -----------------------------
    // Nicht getrimmt: creationell_captcha_evaluate_bypass() trimmt hier
    // ebenfalls nicht, und die Frage ist genau, was der Laufzeitpfad sieht.
    foreach ( (array) ( $settings['bypass_cookies'] ?? [] ) as $raw ) {
        $entry = (string) $raw;
        $pos   = strpos( $entry, '=' );
        if ( false === $pos ) {
            // Ohne Trennzeichen überspringt die Auswertung den Eintrag —
            // wirkungslos, aber auch keine Gefahr. Nicht melden.
            continue;
        }
        $name  = substr( $entry, 0, $pos );
        $value = substr( $entry, $pos + 1 );
        if ( '' === $name || '' !== trim( $value ) ) {
            continue;
        }

        if ( '' === $value ) {
            // Der Laufzeit-Guard (helpers.php, BK-14) überspringt diesen
            // Eintrag inzwischen. Vor dem Fix wäre hash_equals('','') wahr
            // gewesen — ein Freifahrtschein für jeden, der das Cookie leer
            // setzt. Die Meldung sagt genau das und nicht mehr.
            $findings[] = [
                'id'      => 'bypass_cookies|' . $entry,
                'liste'   => __( 'Cookie-Bypass', 'creationell-captcha' ),
                'eintrag' => $entry,
                'wirkung' => 'unwirksam',
                'tab'     => 'firewall',
                'meldung' => __( 'Dieser Eintrag hat keinen Wert. Er wird seit dieser Version übersprungen und wirkt nicht mehr — vorher kam damit jeder durch, der das Cookie leer mitschickte. Zeile entfernen oder einen langen Zufallswert eintragen.', 'creationell-captcha' ),
            ];
            continue;
        }

        // Wert aus reinem Leerraum: der Laufzeitpfad vergleicht ihn weiterhin,
        // die Eingabeprüfung nimmt ihn nicht mehr an. Ein gemeinsames
        // Geheimnis aus einem Leerzeichen ist keines.
        $findings[] = [
            'id'      => 'bypass_cookies|' . $entry,
            'liste'   => __( 'Cookie-Bypass', 'creationell-captcha' ),
            'eintrag' => $entry,
            'wirkung' => 'aktiv',
            'tab'     => 'firewall',
            'meldung' => __( 'Der Wert dieses Eintrags besteht nur aus Leerzeichen. Er wirkt weiterhin: wer das Cookie mit genau diesem Inhalt setzt, ist vom gesamten Schutz ausgenommen — als geheimer Wert ist er wertlos. Zeile entfernen oder einen langen Zufallswert eintragen.', 'creationell-captcha' ),
        ];
    }

    // --- 3. Catch-all im User-Agent-Bypass (BK-9) ----------------------------
    foreach ( (array) ( $settings['bypass_ua_allow'] ?? [] ) as $raw ) {
        if ( ! is_scalar( $raw ) ) {
            continue;
        }
        $pattern = (string) $raw;

        if ( creationell_captcha_hardening_is_catch_all_pattern( $pattern ) ) {
            $findings[] = [
                'id'      => 'bypass_ua_allow|' . trim( $pattern ),
                'liste'   => __( 'User-Agent-Bypass', 'creationell-captcha' ),
                'eintrag' => trim( $pattern ),
                'wirkung' => 'unwirksam',
                'tab'     => 'firewall',
                'meldung' => __( 'Dieses Muster passt auf jeden Browser-Kennzeichner. Es wird seit dieser Version übersprungen und wirkt nicht mehr — vorher war damit jede Anfrage vom gesamten Schutz ausgenommen. Zeile entfernen oder ein konkretes Muster eintragen, etwa *pingdom*.', 'creationell-captcha' ),
            ];
            continue;
        }

        // B-M2: dasselbe Ergebnis ohne blosses Sternchen. Der Laufzeit-Guard
        // greift hier NICHT — das Muster wird ausgewertet und trifft jeden
        // realistischen Kennzeichner. Deshalb `aktiv` und nicht `unwirksam`,
        // und deshalb steht diese Prüfung nach der Catch-all-Prüfung: ein
        // blosses Sternchen trifft die Sonden ebenfalls, gehört aber in die
        // Meldung darüber und darf nicht zweimal auftauchen.
        if ( creationell_captcha_hardening_matches_every_user_agent( $pattern ) ) {
            $findings[] = [
                'id'      => 'bypass_ua_allow|jeder-ua|' . trim( $pattern ),
                'liste'   => __( 'User-Agent-Bypass', 'creationell-captcha' ),
                'eintrag' => trim( $pattern ),
                'wirkung' => 'aktiv',
                'tab'     => 'firewall',
                'meldung' => __( 'Dieses Muster passt auf jeden realistischen Browser- und Werkzeug-Kennzeichner — geprüft gegen Browser, curl, Bibliotheken und Suchmaschinen-Bots. Es ist damit kein Bypass für einzelne Dienste, sondern hebt den gesamten Schutz für jede Anfrage auf, und es wirkt: der Guard gegen ein blosses Sternchen greift bei dieser Schreibweise nicht. Zeile entfernen oder ein konkretes Muster eintragen, etwa *pingdom*.', 'creationell-captcha' ),
            ];
        }
    }

    return $findings;
}

/**
 * Führt den Scan gegen die aktuell gespeicherten Einstellungen aus.
 *
 * @return array<int, array{id: string, liste: string, eintrag: string, wirkung: string, tab: string, meldung: string}>
 */
function creationell_captcha_hardening_findings(): array {
    return creationell_captcha_hardening_scan( creationell_captcha_get_settings() );
}

/**
 * Kurzkennung des aktuellen Fundbildes.
 *
 * Ein: `id` und `wirkung`. Nicht der Meldungstext — sonst ließe eine
 * Umformulierung beim nächsten Update einen bereits weggeklickten Hinweis wieder
 * auftauchen. `wirkung` muss dagegen einfließen: ein `ruhend`-Fund wird zu einem
 * `aktiv`-Fund, sobald der Betreiber die zugehörige Funktion einschaltet, ohne
 * dass sich die `id` ändert. Ohne dieses Feld bliebe die ausgeblendete Warnung
 * auch dann ausgeblendet, wenn aus der Tretmine ein Loch geworden ist.
 *
 * Umgekehrt bringt ein NEUER oder geänderter Fund den Hinweis zurück, obwohl
 * der Benutzer den vorigen weggeklickt hat — genau das ist gewollt: ausgeblendet
 * wird ein bestimmtes Fundbild, nicht die Meldung als solche.
 *
 * Die `id` geht gehasht ein, nicht roh: sie enthält gespeicherte Listeneinträge
 * und darf im Zusammenbau kein Trennzeichen zerschießen (ein `bypass_cookies`-
 * Eintrag darf jedes Zeichen enthalten, auch Tabulator und Zeilenumbruch).
 *
 * @param array<int, array<string, string>> $findings Fundliste aus dem Scan.
 * @return string 16 Hex-Zeichen, oder '' wenn es nichts zu melden gibt.
 */
function creationell_captcha_hardening_fingerprint( array $findings ): string {
    if ( [] === $findings ) {
        return '';
    }

    $rows = array_map(
        static fn( array $f ): string => (string) ( $f['wirkung'] ?? '' )
            . ' ' . hash( 'sha256', (string) ( $f['id'] ?? '' ) ),
        $findings
    );
    sort( $rows );

    return substr( hash( 'sha256', implode( "\n", $rows ) ), 0, 16 );
}

/**
 * Baut das Ziel des Redirects nach dem Ausblenden-Klick: dieselbe Seite ohne
 * den Ausblenden-Parameter und ohne die Nonce.
 *
 * Wirkung des ursprünglichen Fundes war gering und ist es geblieben: Der
 * Handler hängt hinter `current_user_can( 'manage_options' )` und
 * `check_admin_referer()`, ein Administrator müsste also selbst eine
 * `//`-Schreibweise einer wp-admin-URL aufrufen, und `wp_safe_redirect()`
 * fängt einen fremden Host ohnehin ab. Der Ausgang war der von N1 an der
 * Under-Attack-Stelle beschriebene: statt zurück auf die Seite, von der er
 * kam, landete der Administrator auf der wp-admin-Startseite — und der
 * Hinweis, den er gerade weggeklickt hat, wäre dort erneut zu sehen.
 *
 * @since 1.1.0
 *
 * @return string Relativer Ziel-URI für wp_safe_redirect().
 */
function creationell_captcha_hardening_dismiss_redirect_target(): string {
    return (string) remove_query_arg(
        [ CREATIONELL_CAPTCHA_HARDENING_DISMISS_ARG, '_wpnonce' ],
        creationell_captcha_request_target()
    );
}

/**
 * Nimmt den Ausblenden-Klick entgegen.
 *
 * Gespeichert wird die serverseitig NEU BERECHNETE Kennung, nicht die aus der
 * URL. Sonst ließe sich mit einem präparierten Link ein Fundbild ausblenden,
 * das es noch gar nicht gibt — der Hinweis wäre schon weggeklickt, bevor er
 * das erste Mal fällig wird.
 */
function creationell_captcha_hardening_handle_dismiss(): void {
    if ( ! isset( $_GET[ CREATIONELL_CAPTCHA_HARDENING_DISMISS_ARG ] ) ) {
        return;
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    check_admin_referer( CREATIONELL_CAPTCHA_HARDENING_DISMISS_ARG );

    $current = creationell_captcha_hardening_fingerprint( creationell_captcha_hardening_findings() );
    if ( '' !== $current ) {
        update_user_meta( get_current_user_id(), CREATIONELL_CAPTCHA_HARDENING_DISMISS_META, $current );
    }

    wp_safe_redirect( creationell_captcha_hardening_dismiss_redirect_target() );
    exit;
}
add_action( 'admin_init', 'creationell_captcha_hardening_handle_dismiss' );

/**
 * Zeigt die gefundene Bestandskonfiguration als Admin-Hinweis.
 *
 * Auf allen Admin-Seiten, nicht nur auf den Plugin-Seiten: es geht um einen
 * Schutz, der gerade nicht greift, und wer das erfahren soll, muss dafür nicht
 * erst zufällig die Einstellungsseite öffnen. Damit der Hinweis trotzdem keine
 * Tapete wird, ist er pro Benutzer ausblendbar (und kommt bei einem neuen Fund
 * von selbst zurück, siehe creationell_captcha_hardening_fingerprint()).
 *
 * Nur für Benutzer mit `manage_options` — niemand sonst könnte etwas ändern,
 * und die Meldung nennt Details der Firewall-Konfiguration.
 */
function creationell_captcha_hardening_render_notice(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $findings = creationell_captcha_hardening_findings();
    if ( [] === $findings ) {
        return;
    }

    $fingerprint = creationell_captcha_hardening_fingerprint( $findings );
    $dismissed   = (string) get_user_meta( get_current_user_id(), CREATIONELL_CAPTCHA_HARDENING_DISMISS_META, true );
    if ( $dismissed === $fingerprint ) {
        return;
    }

    // Rot nur, wenn wirklich gerade etwas offen steht. `ruhend` und `unwirksam`
    // gehören gemeldet, aber nicht in Alarmfarbe: eine rote Fehlermeldung über
    // einen Optionswert, den zur Laufzeit kein Codepfad liest, ist genau die
    // Sorte Warnung, die den Betreiber zum Wegklicken erzieht — und die nächste,
    // die wirklich zählt, klickt er dann mit weg.
    $has_active = false;
    foreach ( $findings as $finding ) {
        if ( 'aktiv' === $finding['wirkung'] ) {
            $has_active = true;
            break;
        }
    }

    // DRITTES Argument zwingend: ohne URL-Argument liest add_query_arg()
    // $_SERVER['REQUEST_URI'] roh — siehe den Docblock von
    // creationell_captcha_request_target(). Der Rückweg (die
    // Redirect-Funktion) benutzt dieselbe Wurzel; beide Hälften des
    // Ausblenden-Vorgangs hängen damit an derselben Pfadableitung.
    $dismiss_url = wp_nonce_url(
        add_query_arg(
            CREATIONELL_CAPTCHA_HARDENING_DISMISS_ARG,
            $fingerprint,
            creationell_captcha_request_target()
        ),
        CREATIONELL_CAPTCHA_HARDENING_DISMISS_ARG
    );
    ?>
    <div class="notice <?php echo $has_active ? 'notice-error' : 'notice-warning'; ?>">
        <p>
            <strong><?php echo esc_html__( 'CreaCaptcha: gespeicherte Einstellungen prüfen', 'creationell-captcha' ); ?></strong><br>
            <?php echo esc_html__( 'Diese Einträge stammen aus einer früheren Version und werden heute nicht mehr angenommen. CreaCaptcha ändert sie nicht von selbst — bitte einmal ansehen:', 'creationell-captcha' ); ?>
        </p>
        <ul style="list-style:disc;margin-left:20px;">
            <?php foreach ( $findings as $finding ) : ?>
                <li>
                    <strong><?php echo esc_html( $finding['liste'] ); ?></strong>
                    <?php
                    /*
                     * B-M13: Der Eintrag lief bis Modul 27 durch esc_html() UND
                     * wurde in ein bereits mit esc_html__() maskiertes Format
                     * eingesetzt — ein `&` im gespeicherten Eintrag erschien im
                     * Backend als `&amp;`. Jetzt wird genau einmal maskiert:
                     * das Format kommt roh aus __(), der eingesetzte Wert und
                     * das Ergebnis laufen zusammen durch esc_html().
                     */
                    echo esc_html(
                        sprintf(
                            /* translators: %s: der beanstandete Eintrag, wörtlich wie gespeichert. */
                            __( '— Eintrag „%s":', 'creationell-captcha' ),
                            $finding['eintrag']
                        )
                    );
                    ?>
                    <?php echo esc_html( $finding['meldung'] ); ?>
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=creationell-captcha&tab=' . $finding['tab'] ) ); ?>"><?php echo esc_html__( '→ zur Einstellung', 'creationell-captcha' ); ?></a>
                </li>
            <?php endforeach; ?>
        </ul>
        <p>
            <a href="<?php echo esc_url( $dismiss_url ); ?>"><?php echo esc_html__( 'Diesen Hinweis ausblenden', 'creationell-captcha' ); ?></a>
        </p>
    </div>
    <?php
}
add_action( 'admin_notices', 'creationell_captcha_hardening_render_notice' );
