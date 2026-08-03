<?php
/**
 * Version-gated upgrade routine.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Runs schema migrations when the stored version differs from the running one.
 *
 * Hooked on admin_init and gated twice — see the inline notes on DS-2. When
 * the event-log table already exists it is re-run through dbDelta so new
 * columns are added; a missing table is created only when
 * `analytics_event_log` says it should exist (DS-4).
 */
function creationell_captcha_maybe_upgrade(): void {
    // DS-2, context gate: `admin_init` is not an "inside wp-admin" signal.
    // wp-admin/admin-ajax.php fires it before the nopriv dispatch and
    // wp-admin/admin-post.php before its own action lookup, so a plain
    // `POST /wp-admin/admin-ajax.php` used to reach dbDelta()/ALTER TABLE with
    // no session at all — and two of them in parallel raced each other.
    //
    // wp_doing_ajax() reads the DOING_AJAX constant that admin-ajax.php itself
    // defines; it is not derived from request data, so a caller cannot unset
    // it. Heartbeat alone hits that endpoint every 15–60 s per open tab, which
    // makes it by far the likeliest place for two concurrent migrations.
    if ( wp_doing_ajax() ) {
        return;
    }

    // DS-2, capability gate: this is the part an anonymous request cannot
    // satisfy — a logged-out visitor holds no capabilities whatsoever, so the
    // repro from the finding (anonymous admin-ajax/-post) is closed outright.
    // `manage_options` is the same capability that guards the settings screen
    // whose sanitize callback performs the very same schema work.
    //
    // What this does NOT claim: admin-post.php with an authenticated
    // administrator still reaches the routine. That is a privileged caller,
    // and the routine stays idempotent (version gate, SHOW INDEX guard,
    // array_key_exists guard) for exactly that reason.
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $stored = (string) get_option( 'creationell_captcha_version', '' );
    if ( $stored === CREATIONELL_CAPTCHA_VERSION ) {
        return;
    }

    $analytics = creationell_captcha_analytics();
    $settings  = creationell_captcha_get_settings();

    /*
     * DS-4 self-heal — and W3-3: what it does NOT do.
     *
     * A write path that bypassed the settings write hook can leave
     * `analytics_event_log` on with no table behind it; log_row() then skips
     * the insert. Creating the table is safe HERE — authenticated
     * administrator, not an AJAX request — but the version gate eleven lines
     * up means this runs only when the STORED version differs from the running
     * one, i.e. once per plugin update.
     *
     * So this is not a repair that comes around on the next login. An admin who
     * ran `wp option patch analytics_event_log 1` and waits for self-healing
     * waits until the next version change. What works right away is
     * `wp creacaptcha repair`, or saving the settings screen with an actual
     * change (creationell_captcha_sync_event_log_table(), settings.php) — the
     * two the log message in Analytics::log_row() names.
     */
    if ( $analytics->table_exists() || ! empty( $settings['analytics_event_log'] ) ) {
        $analytics->ensure_table();
    }

    creationell_captcha_migrate_widget_mode();

    update_option( 'creationell_captcha_version', CREATIONELL_CAPTCHA_VERSION );
}
add_action( 'admin_init', 'creationell_captcha_maybe_upgrade' );

/**
 * Migrates the legacy `widget_mode` setting (Modul 11a) to the new
 * `widget_display` + `widget_auto_trigger` pair (Modul 14). Idempotent — if
 * `widget_display` is already present in the stored option, the migration is
 * skipped.
 *
 * Mapping:
 *   visible → widget_display=standard,  widget_auto_trigger=none
 *   auto    → widget_display=invisible, widget_auto_trigger=onload
 *   overlay → widget_display=floating,  widget_auto_trigger=onsubmit
 *
 * Den Alt-Schlüssel `widget_mode` nimmt die Migration aus dem Wertesatz, den
 * sie übergibt; ab Modul 14 wird er nirgends mehr gelesen. Ob er damit aus der
 * Option verschwindet, entscheidet der Sanitizer: Er trägt am Ende jeden
 * Schlüssel nach, der zwar gespeichert ist, aber nicht in der
 * Feldspezifikation steht (Carry-over für den Toggle eines gerade inaktiven
 * Formular-Plugins) — und er liest dafür den Stand VOR diesem Schreibvorgang.
 * Im wp-admin, wo er zusätzlich als `sanitize_option`-Filter hängt, kommt
 * `widget_mode` deshalb zurück. Folgenlos: keine Codestelle wertet den
 * Schlüssel noch aus, und `creationell_captcha_get_settings()` merged ohnehin
 * über die Defaults. Aus demselben Grund ist der Aufräum-Zweig unten
 * (`widget_display` vorhanden, `widget_mode` noch da) dort ein Schreibvorgang
 * ohne Änderung.
 */
function creationell_captcha_migrate_widget_mode(): void {
    $stored = get_option( 'creationell_captcha_settings', [] );
    if ( ! is_array( $stored ) ) {
        return;
    }

    // Idempotency guard: if the user has already saved settings under v0.20.0,
    // widget_display will be present and we have nothing to migrate.
    if ( array_key_exists( 'widget_display', $stored ) ) {
        if ( array_key_exists( 'widget_mode', $stored ) ) {
            unset( $stored['widget_mode'] );
            creationell_captcha_store_migrated_settings( $stored );
        }
        return;
    }

    $mode = isset( $stored['widget_mode'] ) ? (string) $stored['widget_mode'] : 'visible';

    $map = [
        'visible' => [ 'display' => 'standard',  'trigger' => 'none' ],
        'auto'    => [ 'display' => 'invisible', 'trigger' => 'onload' ],
        'overlay' => [ 'display' => 'floating',  'trigger' => 'onsubmit' ],
    ];

    $target = $map[ $mode ] ?? $map['visible'];

    $stored['widget_display']      = $target['display'];
    $stored['widget_auto_trigger'] = $target['trigger'];

    unset( $stored['widget_mode'] );

    creationell_captcha_store_migrated_settings( $stored );
}

/**
 * Writes a migrated settings array back — through the sanitiser, with the
 * write context pinned.
 *
 * B-M6: Die Migration schrieb den rohen Options-Inhalt zurück. Heute ist das
 * folgenlos (der Pfad läuft nur im wp-admin, wo der `sanitize_option`-Filter
 * hängt, und die gesetzten Werte stammen aus einer Konstantentabelle), aber es
 * ist derselbe Bauart-Fehler wie in `settings-manager.php`: Ob sanitisiert
 * wird, hing am Request-Kontext statt am Aufrufer. Der Kontext ist
 * PROGRAMMATIC — der übergebene Wertesatz ist vollständig und bewusst gewählt,
 * die `requires`-Rückschreibung der Formular-Semantik würde eine vom Sanitizer
 * verworfene Eingabe wieder einsetzen.
 *
 * Was diese Funktion NICHT leistet: einen Schlüssel aus der Option entfernen.
 * Die Nachtrags-Schleife am Ende des Sanitizers setzt jeden gespeicherten
 * Schlüssel wieder ein, der nicht in der Feldspezifikation steht — sie liest
 * dabei den Stand VOR diesem Schreibvorgang. Ein `unset()` hier würde nur in
 * einem Request ohne `sanitize_option`-Filter wirken und genau die
 * Kontextabhängigkeit wiederherstellen, die dieser Fix beseitigt. Der
 * Alt-Schlüssel `widget_mode` bleibt deshalb gegebenenfalls stehen; er wird
 * nirgends mehr gelesen (siehe Docblock der Migration).
 *
 * @param array<string, mixed> $settings Migrierter Wertesatz.
 */
function creationell_captcha_store_migrated_settings( array $settings ): void {
    creationell_captcha_with_sanitize_context(
        CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC,
        static function () use ( $settings ): void {
            update_option(
                'creationell_captcha_settings',
                creationell_captcha_sanitize_settings(
                    $settings,
                    CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC
                )
            );
        }
    );
}
