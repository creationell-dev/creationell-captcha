<?php
/**
 * Shared tab-UI helpers for the plugin's tab-organised admin pages.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Records and reports the admin-page hook suffixes of the plugin's
 * tab-organised pages.
 *
 * A submenu page's hook suffix derives from the sanitised parent menu *title*,
 * not its slug, so it cannot be reliably hardcoded. Each tabbed page passes the
 * value WordPress returns from add_menu_page()/add_submenu_page() here, and the
 * admin asset loader matches the current screen against the recorded set.
 *
 * @param mixed $add Hook suffix to record; ignored unless a non-empty string.
 * @return array<int, string> All recorded hook suffixes.
 */
function creationell_captcha_tabbed_page_hooks( mixed $add = null ): array {
    static $hooks = [];

    if ( is_string( $add ) && '' !== $add && ! in_array( $add, $hooks, true ) ) {
        $hooks[] = $add;
    }

    return $hooks;
}

/**
 * Determines the active tab from the request, whitelisted against $tabs.
 *
 * Falls back to the first tab when no valid `tab` query parameter is present.
 * The value only selects which panel is shown and is strictly whitelisted
 * against the given registry, so no nonce check is required.
 *
 * @param array<string, string> $tabs Tab registry (id => label).
 * @return string Active tab id.
 */
function creationell_captcha_active_tab( array $tabs ): string {
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab selection, whitelisted below.
    $requested = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( (string) $_GET['tab'] ) ) : '';

    if ( array_key_exists( $requested, $tabs ) ) {
        return $requested;
    }

    return (string) array_key_first( $tabs );
}

/**
 * Renders the no-JavaScript fallback style and the nav-tab bar.
 *
 * Without JavaScript the per-tab panels would each be hidden by admin.css; the
 * <noscript> override makes every panel visible again. Exactly one tab link is
 * marked active.
 *
 * @param array<string, string> $tabs       Tab registry (id => label).
 * @param string                $active_tab Active tab id.
 * @param string                $base_url   Page URL the tab links point at.
 */
function creationell_captcha_render_nav_tabs( array $tabs, string $active_tab, string $base_url ): void {
    ?>
    <noscript>
        <style>.creationell-captcha-tab { display: block !important; }</style>
    </noscript>

    <h2 class="nav-tab-wrapper creationell-captcha-tabs-nav">
        <?php foreach ( $tabs as $tab_id => $tab_label ) : ?>
            <a
                href="<?php echo esc_url( add_query_arg( 'tab', $tab_id, $base_url ) ); ?>"
                class="nav-tab<?php echo $tab_id === $active_tab ? ' nav-tab-active' : ''; ?>"
                data-tab="<?php echo esc_attr( $tab_id ); ?>"
            ><?php echo esc_html( $tab_label ); ?></a>
        <?php endforeach; ?>
    </h2>
    <?php
}
