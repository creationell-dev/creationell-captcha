<?php
/**
 * admin-post.php action handlers for the "Werkzeuge" page.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Stores a one-shot admin notice and redirects back to the Werkzeuge page.
 *
 * @param string $type    'success' or 'error'.
 * @param string $message Notice text.
 */
function creationell_captcha_tools_redirect( string $type, string $message ): never {
    set_transient(
        'creationell_captcha_tools_notice_' . get_current_user_id(),
        [
            'type'    => $type,
            'message' => $message,
        ],
        60
    );
    wp_safe_redirect( admin_url( 'admin.php?page=creationell-captcha-tools' ) );
    exit;
}

/**
 * Guards a tools action: requires manage_options and a valid nonce.
 *
 * @param string $action The nonce action name.
 */
function creationell_captcha_tools_guard( string $action ): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die(
            esc_html__( 'Keine Berechtigung.', 'creationell-captcha' ),
            '',
            [ 'response' => 403 ]
        );
    }
    check_admin_referer( $action );
}

/**
 * Streams the current settings as a JSON download.
 */
function creationell_captcha_handle_export_settings(): void {
    creationell_captcha_tools_guard( 'creationell_captcha_export_settings' );

    nocache_headers();
    header( 'Content-Type: application/json; charset=utf-8' );
    header(
        'Content-Disposition: attachment; filename="creationell-captcha-settings-'
        . gmdate( 'Y-m-d' ) . '.json"'
    );

    echo wp_json_encode(
        creationell_captcha_export_settings(),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
    exit;
}
add_action( 'admin_post_creationell_captcha_export_settings', 'creationell_captcha_handle_export_settings' );

/**
 * Handles the settings-import upload.
 */
function creationell_captcha_handle_import_settings(): void {
    creationell_captcha_tools_guard( 'creationell_captcha_import_settings' );

    $file = $_FILES['creationell_captcha_import_file'] ?? null;

    if ( ! is_array( $file )
        || ! isset( $file['tmp_name'], $file['error'] )
        || UPLOAD_ERR_OK !== (int) $file['error']
        || ! is_uploaded_file( (string) $file['tmp_name'] )
    ) {
        creationell_captcha_tools_redirect(
            'error',
            __( 'Import fehlgeschlagen: keine Datei empfangen.', 'creationell-captcha' )
        );
    }

    $size = filesize( (string) $file['tmp_name'] );
    if ( false === $size || $size > 1048576 ) {
        creationell_captcha_tools_redirect(
            'error',
            __( 'Import fehlgeschlagen: die Datei ist zu groß (max. 1 MiB).', 'creationell-captcha' )
        );
    }

    $raw     = (string) file_get_contents( (string) $file['tmp_name'] );
    $payload = json_decode( $raw, true );

    if ( ! is_array( $payload ) ) {
        creationell_captcha_tools_redirect(
            'error',
            __( 'Import fehlgeschlagen: die Datei ist kein gültiges JSON.', 'creationell-captcha' )
        );
    }

    $result = creationell_captcha_import_settings( $payload );

    if ( is_wp_error( $result ) ) {
        creationell_captcha_tools_redirect( 'error', $result->get_error_message() );
    }

    // AF-6: Der Import ist ein Vollersatz und die Datei ist ungeprüfter
    // Herkunft — beides wird jetzt in der Erfolgsmeldung benannt, statt es
    // stillschweigend zu tun.
    $message = __( 'Einstellungen importiert — die bisherige Konfiguration wurde vollständig ersetzt.', 'creationell-captcha' );
    if ( ! empty( $result['source_notice'] ) ) {
        $message .= ' ' . $result['source_notice'];
    }
    if ( ! empty( $result['version_notice'] ) ) {
        $message .= ' ' . $result['version_notice'];
    }

    // AF-4: Der Import läuft über admin-post.php und endet in einem Redirect —
    // die add_settings_error()-Warnungen des Sanitizers (verworfene IP-Zeilen,
    // ungültiges Strings-JSON, Argon2id-Downgrade) gingen dabei verloren, weil
    // sie nur im Request-globalen Array stehen. Sie werden hier eingesammelt
    // und in die Werkzeuge-Meldung übernommen.
    foreach ( creationell_captcha_collect_settings_error_messages() as $warning ) {
        $message .= ' ' . $warning;
    }

    creationell_captcha_tools_redirect( 'success', $message );
}
add_action( 'admin_post_creationell_captcha_import_settings', 'creationell_captcha_handle_import_settings' );

/**
 * Collects the plugin's queued settings-error messages, de-duplicated.
 *
 * Der Sanitizer läuft auf dem Importweg zweimal (einmal explizit, einmal über
 * den `sanitize_option`-Filter in `update_option()`), meldet identische Funde
 * also doppelt — deshalb `array_unique`.
 *
 * @return array<int, string>
 */
function creationell_captcha_collect_settings_error_messages(): array {
    if ( ! function_exists( 'get_settings_errors' ) ) {
        return [];
    }

    $messages = [];
    foreach ( get_settings_errors( 'creationell_captcha_settings' ) as $error ) {
        $text = trim( (string) ( $error['message'] ?? '' ) );
        if ( '' !== $text ) {
            $messages[] = $text;
        }
    }

    return array_values( array_unique( $messages ) );
}

/**
 * Handles the full factory reset.
 */
function creationell_captcha_handle_reset_settings(): void {
    creationell_captcha_tools_guard( 'creationell_captcha_reset_settings' );
    creationell_captcha_reset_settings();
    // AF-3: Diese Meldung war bis zum Kontext-Fix falsch — die gegateten Listen
    // (code_challenge_watchlist, firewall_trusted_proxies) überlebten den
    // Backend-Reset, weil der sanitize_option-Filter sie mit Formular-Semantik
    // aus dem Altzustand zurückschrieb. creationell_captcha_reset_settings()
    // heftet den programmatischen Kontext jetzt explizit an; die Listen werden
    // tatsächlich geleert, die Meldung stimmt.
    creationell_captcha_tools_redirect(
        'success',
        __( 'Auf Werkseinstellungen zurückgesetzt; die Listen wurden geleert.', 'creationell-captcha' )
    );
}
add_action( 'admin_post_creationell_captcha_reset_settings', 'creationell_captcha_handle_reset_settings' );

/**
 * Handles "load defaults" (keeps the lists).
 */
function creationell_captcha_handle_load_defaults(): void {
    creationell_captcha_tools_guard( 'creationell_captcha_load_defaults' );
    creationell_captcha_load_default_settings();
    creationell_captcha_tools_redirect(
        'success',
        __( 'Standardwerte geladen; die Listen blieben erhalten.', 'creationell-captcha' )
    );
}
add_action( 'admin_post_creationell_captcha_load_defaults', 'creationell_captcha_handle_load_defaults' );

/**
 * Triggers a manual Cloudflare-range refresh from the Werkzeuge page.
 */
function creationell_captcha_handle_cloudflare_refresh(): void {
    creationell_captcha_tools_guard( 'creationell_captcha_cloudflare_refresh' );

    $result = creationell_captcha_refresh_cloudflare_ips_now();

    if ( ! $result['ok'] ) {
        creationell_captcha_tools_redirect(
            'error',
            sprintf(
                /* translators: %s: error message from the refresh helper. */
                __( 'Cloudflare-Aktualisierung fehlgeschlagen: %s', 'creationell-captcha' ),
                $result['error'] ?? __( 'unbekannter Fehler', 'creationell-captcha' )
            )
        );
    }

    creationell_captcha_tools_redirect(
        'success',
        sprintf(
            /* translators: 1: IPv4 count, 2: IPv6 count. */
            __( 'Cloudflare-Ranges aktualisiert: %1$d IPv4, %2$d IPv6.', 'creationell-captcha' ),
            (int) $result['v4'],
            (int) $result['v6']
        )
    );
}
add_action( 'admin_post_creationell_captcha_cloudflare_refresh', 'creationell_captcha_handle_cloudflare_refresh' );

/**
 * Empties the cached Cloudflare-range option from the Werkzeuge page.
 */
function creationell_captcha_handle_cloudflare_clear(): void {
    creationell_captcha_tools_guard( 'creationell_captcha_cloudflare_clear' );

    if ( creationell_captcha_clear_cloudflare_cache() ) {
        creationell_captcha_tools_redirect(
            'success',
            __( 'Cloudflare-IP-Cache geleert. Nächster Zugriff nutzt die gebündelten Ranges.', 'creationell-captcha' )
        );
    }

    creationell_captcha_tools_redirect(
        'success',
        __( 'Kein Cache vorhanden — nichts zu leeren.', 'creationell-captcha' )
    );
}
add_action( 'admin_post_creationell_captcha_cloudflare_clear', 'creationell_captcha_handle_cloudflare_clear' );
