<?php
/**
 * Shared settings-management service.
 *
 * Export, import, reset and "load defaults" — used by both the backend
 * "Werkzeuge" page and the WP-CLI commands.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Schema version of the settings-export format.
 */
const CREATIONELL_CAPTCHA_EXPORT_SCHEMA = 1;

/**
 * Setting keys whose value is a list (every `textarea` field).
 *
 * Derived from the field specification so the list never drifts. "Load
 * defaults" preserves these keys; "reset" clears them.
 *
 * @return array<int, string>
 */
function creationell_captcha_list_setting_keys(): array {
    $keys = [];
    foreach ( creationell_captcha_settings_fields() as $key => $field ) {
        if ( isset( $field['type'] ) && 'textarea' === $field['type'] ) {
            $keys[] = $key;
        }
    }

    return $keys;
}

/**
 * Builds the settings-export payload.
 *
 * The HMAC secrets are deliberately excluded — they must never leave the site.
 *
 * @return array<string, mixed>
 */
function creationell_captcha_export_settings(): array {
    return [
        'plugin'         => 'creationell-captcha',
        'type'           => 'settings-export',
        'schema'         => CREATIONELL_CAPTCHA_EXPORT_SCHEMA,
        'plugin_version' => CREATIONELL_CAPTCHA_VERSION,
        'exported_at'    => gmdate( 'c' ),
        'site_url'       => home_url(),
        'settings'       => creationell_captcha_get_settings(),
    ];
}

/**
 * Validates and applies a settings-export payload.
 *
 * The `settings` array is run through creationell_captcha_sanitize_settings(),
 * so the same guarantees as the settings form apply: whitelisted selects,
 * clamped numbers, bounded lists, unknown keys dropped, missing keys defaulted.
 *
 * @param array<string, mixed> $payload Decoded export payload.
 * @return array<string, mixed>|WP_Error On success: { imported, version_notice, source_notice }.
 */
function creationell_captcha_import_settings( array $payload ): array|WP_Error {
    if ( ( $payload['plugin'] ?? '' ) !== 'creationell-captcha'
        || ( $payload['type'] ?? '' ) !== 'settings-export'
    ) {
        return new WP_Error(
            'creationell_captcha_import_invalid',
            __( 'Die Datei ist keine gültige CreaCaptcha-Einstellungsdatei.', 'creationell-captcha' )
        );
    }

    if ( (int) ( $payload['schema'] ?? 0 ) !== CREATIONELL_CAPTCHA_EXPORT_SCHEMA ) {
        return new WP_Error(
            'creationell_captcha_import_schema',
            __( 'Das Format dieser Einstellungsdatei wird von dieser Plugin-Version nicht unterstützt.', 'creationell-captcha' )
        );
    }

    if ( ! isset( $payload['settings'] ) || ! is_array( $payload['settings'] ) ) {
        return new WP_Error(
            'creationell_captcha_import_empty',
            __( 'Die Einstellungsdatei enthält keine Einstellungen.', 'creationell-captcha' )
        );
    }

    // AF-1/W1: Ein Import ist ein programmatischer Schreibvorgang — der
    // übergebene Wertesatz ist vollständig und bewusst gewählt. Ohne diese
    // Klammer liefe der über admin-post.php ausgelöste Import in den
    // sanitize_option-Filter mit Formular-Semantik und die
    // requires-Rückschreibung machte importierte Werte gegateter Felder still
    // wieder rückgängig. Die Klammer umfasst beide Sanitizer-Durchläufe: den
    // expliziten hier und den des Filters in update_option().
    $clean = creationell_captcha_with_sanitize_context(
        CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC,
        static function () use ( $payload ): array {
            $sanitized = creationell_captcha_sanitize_settings(
                $payload['settings'],
                CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC
            );
            creationell_captcha_store_settings( $sanitized );

            return $sanitized;
        }
    );

    $version_notice = '';
    $file_version   = (string) ( $payload['plugin_version'] ?? '' );
    if ( '' !== $file_version && $file_version !== CREATIONELL_CAPTCHA_VERSION ) {
        $version_notice = sprintf(
            /* translators: 1: plugin version the file was exported with, 2: current plugin version. */
            __( 'Hinweis: Die Datei wurde mit Version %1$s erstellt, aktuell läuft %2$s.', 'creationell-captcha' ),
            $file_version,
            CREATIONELL_CAPTCHA_VERSION
        );
    }

    // AF-6: Der Import ist ein VOLLERSATZ (nicht genannte Schlüssel fallen auf
    // Default) und die Datei wird nicht auf ihre Herkunft geprüft — es gibt
    // keine Signatur, `site_url` wurde beim Export zwar mitgeschrieben, aber
    // nie ausgewertet. Statt Signaturinfrastruktur zu bauen, wird die Herkunft
    // jetzt wenigstens benannt: der Aufrufer zeigt sie dem Admin an.
    $source_notice = '';
    $source_url    = trim( (string) ( $payload['site_url'] ?? '' ) );
    if ( '' === $source_url ) {
        $source_notice = __( 'Die Datei nennt keine Herkunfts-Website.', 'creationell-captcha' );
    } elseif ( untrailingslashit( $source_url ) !== untrailingslashit( home_url() ) ) {
        $source_notice = sprintf(
            /* translators: %s: site URL the settings file was exported from. */
            __( 'Achtung: Die Datei stammt von einer anderen Website (%s).', 'creationell-captcha' ),
            $source_url
        );
    } else {
        $source_notice = sprintf(
            /* translators: %s: site URL the settings file was exported from. */
            __( 'Herkunft der Datei: %s.', 'creationell-captcha' ),
            $source_url
        );
    }

    return [
        'imported'       => $clean,
        'version_notice' => $version_notice,
        'source_notice'  => $source_notice,
    ];
}

/**
 * Full factory reset: writes the complete default settings array, which also
 * empties every list and drops stored keys outside the current field
 * specification. Secrets, analytics counters and the event log are
 * left untouched.
 */
function creationell_captcha_reset_settings(): void {
    // AF-3/W1: Über admin-post.php feuert admin_init, der sanitize_option-Filter
    // hängt also am update_option() unten. Mit Formular-Semantik restaurierte er
    // die gegateten Listen (code_challenge_watchlist, firewall_trusted_proxies)
    // aus dem Altzustand — der Backend-„Werksreset" leerte sie nicht, der
    // CLI-Reset schon. Der explizit angeheftete Kontext macht beide Wege gleich.
    //
    // E3a: Die Klammer allein reichte nicht. Sie legt den Kontext FEST, falls
    // der Filter läuft — dass er läuft, hängt aber an `admin_init`. Im
    // WP-CLI-Lauf existiert er nicht, dort schrieb der Werksreset vollständig
    // ungeprüft. Deshalb wird der Sanitizer jetzt explizit aufgerufen (wie in
    // creationell_captcha_import_settings()); die Klammer bleibt für den
    // zusätzlichen Filterdurchlauf im wp-admin stehen.
    //
    // Nachlese N6 (Befund 5): …_RESET statt …_PROGRAMMATIC. Der Sanitizer-Aufruf
    // aus E3a brachte dem CLI-Reset die Eingabeprüfung — und nahm ihm zugleich
    // die zweite Hälfte des Werksresets, weil die Übernahme-Schleife des
    // Sanitizers gespeicherte Schlüssel ausserhalb der Feldspezifikation
    // (Schalter gerade inaktiver Formular-Plugins, Reste aus `wp option patch`)
    // wieder eintrug. Der eigene Kontextwert schaltet genau diese Schleife ab;
    // alles andere bleibt PROGRAMMATIC-Semantik. Er steht bewusst AUCH an der
    // Klammer, damit der zusätzliche Filterdurchlauf im wp-admin dieselbe
    // Semantik bekommt — sonst räumte der CLI-Reset auf und der Backend-Reset
    // nicht.
    creationell_captcha_with_sanitize_context(
        CREATIONELL_CAPTCHA_SANITIZE_RESET,
        static function (): void {
            creationell_captcha_store_settings(
                creationell_captcha_sanitize_settings(
                    creationell_captcha_get_default_settings(),
                    CREATIONELL_CAPTCHA_SANITIZE_RESET
                )
            );
        }
    );
}

/**
 * Resets every non-list setting to its default while preserving the current
 * list values (IP block/allow, UA block, interceptor paths).
 *
 * Die übernommenen Listen laufen dabei durch dieselbe Eingabeprüfung wie ein
 * regulärer Speichervorgang (E3a): ein Eintrag, der an den Plugin-Schreibwegen
 * vorbei in die Option kam (`wp option update`, DB-Restore), überlebte
 * „Standardwerte laden" bisher ungeprüft — auch dann, wenn die Prüfung ihn
 * heute ablehnt.
 */
function creationell_captcha_load_default_settings(): void {
    $defaults = creationell_captcha_get_default_settings();
    $current  = creationell_captcha_get_settings();

    foreach ( creationell_captcha_list_setting_keys() as $key ) {
        if ( array_key_exists( $key, $current ) ) {
            $defaults[ $key ] = $current[ $key ];
        }
    }

    // Wie beim Reset: die Listen werden hier bewusst und vollständig
    // mitgegeben, die requires-Rückschreibung des Formularkontexts hätte
    // darüber hinaus auch gegatete Nicht-Listen-Felder eingefroren. Und wie
    // beim Reset genügt die Kontext-Klammer nicht — im WP-CLI-Lauf hängt kein
    // sanitize_option-Filter, den sie festlegen könnte.
    creationell_captcha_with_sanitize_context(
        CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC,
        static function () use ( $defaults ): void {
            creationell_captcha_store_settings(
                creationell_captcha_sanitize_settings(
                    $defaults,
                    CREATIONELL_CAPTCHA_SANITIZE_PROGRAMMATIC
                )
            );
        }
    );
}
