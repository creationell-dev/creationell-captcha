<?php
/**
 * The "Werkzeuge" admin submenu page: settings export, import, reset and
 * "load defaults".
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers the "Werkzeuge" submenu page under the CreaCaptcha menu.
 */
function creationell_captcha_register_tools_page(): void {
    $hook = add_submenu_page(
        'creationell-captcha',
        __( 'Werkzeuge', 'creationell-captcha' ),
        __( 'Werkzeuge', 'creationell-captcha' ),
        'manage_options',
        'creationell-captcha-tools',
        'creationell_captcha_render_tools_page'
    );
    creationell_captcha_tabbed_page_hooks( $hook );
}
add_action( 'admin_menu', 'creationell_captcha_register_tools_page' );

/**
 * Renders the one-shot admin notice left behind by a tools action.
 */
function creationell_captcha_render_tools_notice(): void {
    $key    = 'creationell_captcha_tools_notice_' . get_current_user_id();
    $notice = get_transient( $key );
    if ( ! is_array( $notice ) || empty( $notice['message'] ) ) {
        return;
    }
    delete_transient( $key );

    $class = 'error' === ( $notice['type'] ?? '' ) ? 'notice-error' : 'notice-success';
    printf(
        '<div class="notice %s is-dismissible"><p>%s</p></div>',
        esc_attr( $class ),
        esc_html( (string) $notice['message'] )
    );
}

/**
 * Renders the "Werkzeuge" page.
 */
function creationell_captcha_render_tools_page(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $action_url   = admin_url( 'admin-post.php' );
    $reset_confirm   = __( 'Wirklich alle Einstellungen inklusive aller gepflegten Listen (IP-Block-/Allow-, User-Agent-, Bypass-, Interceptor-Pfade & -Actions) auf Werkseinstellungen zurücksetzen?', 'creationell-captcha' );
    $defaults_confirm = __( 'Alle Konfigurationswerte auf Standard zurücksetzen? Die Listen bleiben erhalten.', 'creationell-captcha' );
    ?>
    <div class="wrap creationell-captcha-tools">
        <h1><?php echo esc_html__( 'CreaCaptcha — Werkzeuge', 'creationell-captcha' ); ?></h1>
        <?php creationell_captcha_render_tools_notice(); ?>

        <div class="creationell-captcha-tool-card card">
            <h2><?php echo esc_html__( 'Einstellungen exportieren', 'creationell-captcha' ); ?></h2>
            <p><?php echo esc_html__( 'Lädt die aktuelle Konfiguration als JSON-Datei herunter. Die HMAC-Sicherheitsschlüssel sind nicht enthalten.', 'creationell-captcha' ); ?></p>
            <form method="post" action="<?php echo esc_url( $action_url ); ?>">
                <input type="hidden" name="action" value="creationell_captcha_export_settings">
                <?php wp_nonce_field( 'creationell_captcha_export_settings' ); ?>
                <p class="submit">
                    <button type="submit" class="button button-secondary"><?php echo esc_html__( 'Exportieren', 'creationell-captcha' ); ?></button>
                </p>
            </form>
        </div>

        <div class="creationell-captcha-tool-card card">
            <h2><?php echo esc_html__( 'Einstellungen importieren', 'creationell-captcha' ); ?></h2>
            <p><?php echo esc_html__( 'Lädt eine zuvor exportierte JSON-Datei. Die bestehende Konfiguration wird vollständig ersetzt.', 'creationell-captcha' ); ?></p>
            <form method="post" action="<?php echo esc_url( $action_url ); ?>" enctype="multipart/form-data">
                <input type="hidden" name="action" value="creationell_captcha_import_settings">
                <?php wp_nonce_field( 'creationell_captcha_import_settings' ); ?>
                <p><input type="file" name="creationell_captcha_import_file" accept=".json,application/json" required></p>
                <p class="submit">
                    <button type="submit" class="button button-secondary"><?php echo esc_html__( 'Importieren', 'creationell-captcha' ); ?></button>
                </p>
            </form>
        </div>

        <div class="creationell-captcha-tool-card card">
            <h2><?php echo esc_html__( 'Auf Werkseinstellungen zurücksetzen', 'creationell-captcha' ); ?></h2>
            <div class="notice notice-warning inline" style="margin-top:0;">
                <p><strong><?php echo esc_html__( 'Achtung — destruktiv:', 'creationell-captcha' ); ?></strong>
                <?php echo esc_html__( 'Diese Option leert auch die gepflegten IP-, User-Agent-, Bypass- und Interceptor-Listen — das ist meist nicht gewünscht. Für das Zurücksetzen der Konfiguration unter Beibehaltung der Listen die nächste Karte „Standardwerte laden" verwenden.', 'creationell-captcha' ); ?></p>
            </div>
            <p><?php echo esc_html__( 'Setzt alle Einstellungen auf die Standardwerte zurück — einschließlich aller gepflegten IP-, User-Agent-, Bypass- und Interceptor-Listen, die dabei geleert werden.', 'creationell-captcha' ); ?></p>
            <form method="post" action="<?php echo esc_url( $action_url ); ?>">
                <input type="hidden" name="action" value="creationell_captcha_reset_settings">
                <?php wp_nonce_field( 'creationell_captcha_reset_settings' ); ?>
                <p class="submit">
                    <button type="submit" class="button button-secondary creationell-captcha-confirm" data-confirm="<?php echo esc_attr( $reset_confirm ); ?>"><?php echo esc_html__( 'Zurücksetzen', 'creationell-captcha' ); ?></button>
                </p>
            </form>
        </div>

        <div class="creationell-captcha-tool-card card">
            <h2><?php echo esc_html__( 'Standardwerte laden', 'creationell-captcha' ); ?></h2>
            <p><?php echo esc_html__( 'Setzt alle Konfigurationswerte auf den Standard zurück, behält aber die gepflegten IP- und User-Agent-Listen sowie die Interceptor-Pfade.', 'creationell-captcha' ); ?></p>
            <form method="post" action="<?php echo esc_url( $action_url ); ?>">
                <input type="hidden" name="action" value="creationell_captcha_load_defaults">
                <?php wp_nonce_field( 'creationell_captcha_load_defaults' ); ?>
                <p class="submit">
                    <button type="submit" class="button button-secondary creationell-captcha-confirm" data-confirm="<?php echo esc_attr( $defaults_confirm ); ?>"><?php echo esc_html__( 'Standardwerte laden', 'creationell-captcha' ); ?></button>
                </p>
            </form>
        </div>

        <div class="creationell-captcha-tool-card card">
            <h2><?php echo esc_html__( 'Cloudflare-IP-Cache', 'creationell-captcha' ); ?></h2>
            <?php creationell_captcha_render_cloudflare_status(); ?>
            <p>
                <form method="post" action="<?php echo esc_url( $action_url ); ?>" style="display:inline-block;margin-right:.5em;">
                    <input type="hidden" name="action" value="creationell_captcha_cloudflare_refresh">
                    <?php wp_nonce_field( 'creationell_captcha_cloudflare_refresh' ); ?>
                    <button type="submit" class="button button-secondary"><?php echo esc_html__( 'Jetzt aktualisieren', 'creationell-captcha' ); ?></button>
                </form>
                <form method="post" action="<?php echo esc_url( $action_url ); ?>" style="display:inline-block;">
                    <input type="hidden" name="action" value="creationell_captcha_cloudflare_clear">
                    <?php wp_nonce_field( 'creationell_captcha_cloudflare_clear' ); ?>
                    <button type="submit" class="button button-secondary creationell-captcha-confirm" data-confirm="<?php echo esc_attr__( 'Den Cloudflare-IP-Cache wirklich leeren?', 'creationell-captcha' ); ?>"><?php echo esc_html__( 'Cache leeren', 'creationell-captcha' ); ?></button>
                </form>
            </p>
        </div>
    </div>
    <?php
}

/**
 * Renders the Cloudflare-cache status block inside the Werkzeuge tool card.
 */
function creationell_captcha_render_cloudflare_status(): void {
    $cached = get_option( 'creationell_captcha_cloudflare_ips', [] );

    if ( ! is_array( $cached ) || empty( $cached ) ) {
        echo '<p>' . esc_html__( 'Kein Cache vorhanden — die gebündelten Cloudflare-Ranges sind aktiv.', 'creationell-captcha' ) . '</p>';
    } else {
        $v4         = is_array( $cached['v4'] ?? null ) ? count( $cached['v4'] ) : 0;
        $v6         = is_array( $cached['v6'] ?? null ) ? count( $cached['v6'] ) : 0;
        $fetched_at = (int) ( $cached['fetched_at'] ?? 0 );
        $source     = (string) ( $cached['source'] ?? '—' );

        echo '<p>';
        if ( $fetched_at > 0 ) {
            printf(
                /* translators: 1: absolute timestamp, 2: relative age. */
                esc_html__( 'Letzter Refresh: %1$s UTC (vor %2$s)', 'creationell-captcha' ),
                esc_html( gmdate( 'Y-m-d H:i:s', $fetched_at ) ),
                esc_html( human_time_diff( $fetched_at, time() ) )
            );
            echo '<br>';
        }
        printf(
            /* translators: 1: IPv4 count, 2: IPv6 count, 3: source label. */
            esc_html__( 'IPv4: %1$d Ranges · IPv6: %2$d Ranges · Quelle: %3$s', 'creationell-captcha' ),
            (int) $v4,
            (int) $v6,
            esc_html( $source )
        );
        echo '</p>';
    }

    $next = wp_next_scheduled( 'creationell_captcha_refresh_cloudflare_ips' );
    if ( false === $next ) {
        echo '<p>' . esc_html__( 'Nächster Cron-Run: kein Cron geplant.', 'creationell-captcha' ) . '</p>';
    } else {
        echo '<p>';
        printf(
            /* translators: 1: absolute timestamp, 2: relative time. */
            esc_html__( 'Nächster Cron-Run: %1$s UTC (in %2$s)', 'creationell-captcha' ),
            esc_html( gmdate( 'Y-m-d H:i:s', (int) $next ) ),
            esc_html( human_time_diff( time(), (int) $next ) )
        );
        echo '</p>';
    }
}
