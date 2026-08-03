<?php
/**
 * Admin menu and tabbed settings page.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers the top-level "CreaCaptcha" admin menu entry.
 */
function creationell_captcha_register_admin_menu(): void {
    $hook = add_menu_page(
        __( 'CreaCaptcha', 'creationell-captcha' ),
        __( 'CreaCaptcha', 'creationell-captcha' ),
        'manage_options',
        'creationell-captcha',
        'creationell_captcha_render_settings_page',
        'dashicons-shield',
        80
    );
    creationell_captcha_tabbed_page_hooks( $hook );
}
add_action( 'admin_menu', 'creationell_captcha_register_admin_menu' );

/**
 * Renders the tabbed settings page.
 *
 * All tabs share one <form> and one submit button — the tab panels are only a
 * display split, so saving always persists every field at once. PHP marks one
 * tab active server-side; admin.js switches tabs client-side; the <noscript>
 * style (emitted by creationell_captcha_render_nav_tabs()) reveals every panel
 * when JavaScript is unavailable.
 */
function creationell_captcha_render_settings_page(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $tabs       = creationell_captcha_admin_tabs();
    $active_tab = creationell_captcha_active_tab( $tabs );
    $base_url   = menu_page_url( 'creationell-captcha', false );
    ?>
    <div class="wrap creationell-captcha-settings creationell-captcha-tabbed">
        <h1><?php echo esc_html__( 'CreaCaptcha', 'creationell-captcha' ); ?></h1>

        <?php
        // AF-4: Diese Seite hängt an add_menu_page(), nicht unter
        // options-general.php — WordPress lädt options-head.php hier nicht und
        // ruft settings_errors() folglich nie auf. Ohne diesen Aufruf landeten
        // alle add_settings_error()-Warnungen des Sanitizers (verworfene
        // IP-Zeilen, ungültiges Strings-JSON, Argon2id→PBKDF2-Downgrade)
        // unsichtbar in der settings_errors-Transiente und tauchten allenfalls
        // verspätet auf einer Kern-Settings-Seite auf.
        //
        // Genau ein Aufruf, keine zweite Ausgabestelle: get_settings_errors()
        // leert die Transiente beim ersten Zugriff, ein zweiter Aufruf zeigte
        // sonst dieselben Meldungen erneut.
        //
        // Bewusst OHNE Slug-Filter: options.php legt in derselben Transiente
        // entweder unsere Warnungen ab oder — wenn keine anfielen — die
        // Kernmeldung „Einstellungen gespeichert" (Gruppe „general"). Ein
        // Filter auf die eigene Gruppe würde die Erfolgsmeldung verschlucken,
        // ohne dass sie anderswo noch erschiene.
        settings_errors();
        ?>

        <?php creationell_captcha_render_nav_tabs( $tabs, $active_tab, $base_url ); ?>

        <form method="post" action="options.php">
            <?php settings_fields( 'creationell_captcha' ); ?>
            <?php foreach ( array_keys( $tabs ) as $tab_id ) : ?>
                <div
                    class="creationell-captcha-tab<?php echo $tab_id === $active_tab ? ' is-active' : ''; ?>"
                    id="creationell-captcha-tab-<?php echo esc_attr( $tab_id ); ?>"
                    data-tab="<?php echo esc_attr( $tab_id ); ?>"
                >
                    <?php do_settings_sections( 'creationell-captcha-tab-' . $tab_id ); ?>
                </div>
            <?php endforeach; ?>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

/**
 * Renders the "an import replaces everything" warning on the Werkzeuge page.
 *
 * AF-6: Der Import prüft nur den Envelope (`plugin`/`type`/`schema`), keine
 * Herkunft — das exportierte `site_url` wurde nie verglichen — und ungenannte
 * Schlüssel fallen auf ihren Default, ein Teilimport ist also ein Vollreset.
 * Das ist `manage_options`-gated und damit kein anonymer Vektor; statt
 * Signaturinfrastruktur bekommt der Vorgang eine Warnhinweis-Ebene: hier vor
 * dem Import, und nach dem Import benennt die Erfolgsmeldung die Herkunft der
 * Datei (siehe creationell_captcha_handle_import_settings()).
 */
function creationell_captcha_render_import_warning(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $screen = get_current_screen();
    if ( ! $screen || false === strpos( (string) $screen->id, 'creationell-captcha-tools' ) ) {
        return;
    }
    ?>
    <div class="notice notice-warning">
        <p>
            <strong><?php echo esc_html__( 'CreaCaptcha — vor dem Import beachten:', 'creationell-captcha' ); ?></strong>
            <?php echo esc_html__( 'Ein Import ersetzt die gesamte Konfiguration. Einstellungen, die in der Datei fehlen, werden auf ihren Standardwert zurückgesetzt — auch Schutzschalter. Die Datei wird nicht auf ihre Herkunft geprüft: nur Dateien importieren, deren Quelle bekannt ist. Vorher die aktuelle Konfiguration exportieren.', 'creationell-captcha' ); ?>
        </p>
    </div>
    <?php
}
add_action( 'admin_notices', 'creationell_captcha_render_import_warning' );

/**
 * Renders the "proxy mode on but trust-set empty" admin notice on plugin pages.
 *
 * The notice is persistent (not dismissible) — it disappears automatically as
 * soon as any trust source is configured.
 */
function creationell_captcha_render_trust_notice(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $screen = get_current_screen();
    if ( ! $screen || false === strpos( (string) $screen->id, 'creationell-captcha' ) ) {
        return;
    }

    $settings = creationell_captcha_get_settings();
    if ( empty( $settings['firewall_behind_proxy'] ) ) {
        return;
    }

    $has_list      = ! empty( $settings['firewall_trusted_proxies'] );
    $has_constant  = [] !== creationell_captcha_trusted_proxies_constant();
    $has_private   = ! empty( $settings['firewall_trust_private_ranges'] );
    $has_cf        = ! empty( $settings['firewall_trust_cloudflare'] );

    if ( $has_list || $has_constant || $has_private || $has_cf ) {
        return;
    }

    $url = admin_url( 'admin.php?page=creationell-captcha&tab=firewall' );
    ?>
    <div class="notice notice-warning">
        <p>
            <strong><?php echo esc_html__( 'CreaCaptcha:', 'creationell-captcha' ); ?></strong>
            <?php echo esc_html__( 'Der Proxy-Modus ist aktiv, aber keine vertrauenswürdigen Proxies konfiguriert. IP-basierte Schutzmaßnahmen wirken aktuell nicht.', 'creationell-captcha' ); ?>
            <a href="<?php echo esc_url( $url ); ?>"><?php echo esc_html__( '→ Einstellungen anpassen', 'creationell-captcha' ); ?></a>
        </p>
    </div>
    <?php
}
add_action( 'admin_notices', 'creationell_captcha_render_trust_notice' );
