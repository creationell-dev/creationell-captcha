<?php
/*
Plugin Name: CreaCaptcha
Plugin URI: https://github.com/creationell-dev/creationell-captcha
Description: Datenschutzfreundlicher Proof-of-Work-Captcha, Firewall, Rate-Limiter, Under-Attack-Modus, E-Mail-Obfuskation und Bild-Code-Challenge — vollständig selbst-gehostet ohne externe Dienste.
Version: 1.1.0
Author: creationell® – die Werbeagentur
Author URI: https://www.creationell.de/
Contributors: creationell-dev
Tags: captcha, spam, anti-spam, anti-bot, proof of work
Requires at least: 6.9
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: creationell-captcha
Domain Path: /languages
*/

declare(strict_types=1);

/*
 * HINWEIS: Der gesamte Code bis zum Umgebungs-Check bleibt bewusst
 * versionstolerant (keine PHP-8-only-Syntax wie benannte Argumente),
 * damit eine veraltete Umgebung eine Admin-Notice zeigt statt zu fatalen.
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

define( 'CREATIONELL_CAPTCHA_VERSION', '1.1.0' );
define( 'CREATIONELL_CAPTCHA_FILE', __FILE__ );
define( 'CREATIONELL_CAPTCHA_BASENAME', plugin_basename( __FILE__ ) );
define( 'CREATIONELL_CAPTCHA_PLUGIN_PATH', plugin_dir_path( __FILE__ ) );
define( 'CREATIONELL_CAPTCHA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'CREATIONELL_CAPTCHA_MIN_PHP', '8.3' );
define( 'CREATIONELL_CAPTCHA_MIN_WP', '6.9' );
define( 'CREATIONELL_CAPTCHA_DEBUG', defined( 'WP_DEBUG' ) && WP_DEBUG );

/*
 * Umgebungs-Check: PHP-Version, WP-Version, geprefixte Bibliothek.
 */
$creationell_captcha_php_ok = version_compare( PHP_VERSION, CREATIONELL_CAPTCHA_MIN_PHP, '>=' );
$creationell_captcha_wp_ok  = version_compare( get_bloginfo( 'version' ), CREATIONELL_CAPTCHA_MIN_WP, '>=' );
$creationell_captcha_lib    = CREATIONELL_CAPTCHA_PLUGIN_PATH . 'lib/autoload.php';
$creationell_captcha_lib_ok = file_exists( $creationell_captcha_lib );

if ( ! $creationell_captcha_php_ok || ! $creationell_captcha_wp_ok || ! $creationell_captcha_lib_ok ) {
    add_action(
        'admin_notices',
        function () use ( $creationell_captcha_php_ok, $creationell_captcha_wp_ok, $creationell_captcha_lib_ok ) {
            if ( ! current_user_can( 'activate_plugins' ) ) {
                return;
            }
            echo '<div class="notice notice-error"><p><strong>CreaCaptcha</strong></p><ul style="list-style:disc;margin-left:20px;">';
            if ( ! $creationell_captcha_php_ok ) {
                printf(
                    '<li>%s</li>',
                    esc_html( sprintf(
                        /* translators: %s: required PHP version. */
                        __( 'Erfordert PHP %s oder neuer.', 'creationell-captcha' ),
                        CREATIONELL_CAPTCHA_MIN_PHP
                    ) )
                );
            }
            if ( ! $creationell_captcha_wp_ok ) {
                printf(
                    '<li>%s</li>',
                    esc_html( sprintf(
                        /* translators: %s: required WordPress version. */
                        __( 'Erfordert WordPress %s oder neuer.', 'creationell-captcha' ),
                        CREATIONELL_CAPTCHA_MIN_WP
                    ) )
                );
            }
            if ( ! $creationell_captcha_lib_ok ) {
                echo '<li>' . esc_html__( 'Abhängigkeiten fehlen — bitte „composer install" im Plugin-Verzeichnis ausführen.', 'creationell-captcha' ) . '</li>';
            }
            echo '</ul></div>';
        }
    );
    return;
}

/*
 * Ab hier sind PHP 8.3+, WordPress 6.9+ und die gebündelte Bibliothek garantiert.
 */
require_once $creationell_captcha_lib;

$creationell_captcha_includes = [
    'includes/helpers.php',
    'includes/rest-context.php',
    'includes/class-plugin-updater.php',
    'includes/class-engine.php',
    'includes/class-interceptor.php',
    'includes/class-firewall.php',
    'includes/class-rate-limiter.php',
    'includes/class-under-attack.php',
    'includes/class-analytics.php',
    'includes/class-email-obfuscator.php',
    'includes/lifecycle.php',
    'includes/settings.php',
    'includes/settings-manager.php',
    'includes/admin-tabs.php',
    'includes/admin-page.php',
    'includes/hardening-migration.php',
    'includes/assets.php',
    'includes/tools-page.php',
    'includes/tools-actions.php',
    'includes/rest.php',
    'includes/code-challenge.php',
    'includes/code-challenge-image.php',
    'includes/widget.php',
    'includes/cloudflare-proxies.php',
    'includes/firewall.php',
    'includes/ratelimit.php',
    'includes/interceptor.php',
    'includes/interceptor-inject.php',
    'includes/under-attack.php',
    'includes/analytics.php',
    'includes/upgrade.php',
    'includes/analytics-page.php',
    'includes/analytics-export.php',
    'includes/cli/bootstrap.php',
    'includes/email-obfuscation.php',
    'includes/forms/comments.php',
    'includes/forms/login.php',
    'includes/forms/registration.php',
    'includes/forms/password-reset.php',
    'includes/integrations/cf7.php',
    'includes/integrations/forminator.php',
    'includes/integrations/wpforms.php',
    'includes/integrations/woocommerce.php',
];

foreach ( $creationell_captcha_includes as $creationell_captcha_include ) {
    $creationell_captcha_path = CREATIONELL_CAPTCHA_PLUGIN_PATH . $creationell_captcha_include;
    if ( file_exists( $creationell_captcha_path ) ) {
        require_once $creationell_captcha_path;
    } elseif ( CREATIONELL_CAPTCHA_DEBUG ) {
        error_log( "[creationell-captcha] Missing include: {$creationell_captcha_include}" );
    }
}

if ( function_exists( 'creationell_captcha_activate' ) ) {
    register_activation_hook( __FILE__, 'creationell_captcha_activate' );
}

if ( function_exists( 'creationell_captcha_deactivate' ) ) {
    register_deactivation_hook( __FILE__, 'creationell_captcha_deactivate' );
}

/*
 * Übersetzungen laden.
 */
add_action(
    'plugins_loaded',
    static function (): void {
        load_plugin_textdomain(
            'creationell-captcha',
            false,
            dirname( CREATIONELL_CAPTCHA_BASENAME ) . '/languages'
        );
    }
);

/*
 * Self-Hosted-GitHub-Updater initialisieren.
 */
add_action(
    'init',
    static function (): void {
        if ( class_exists( 'Creationell\\Captcha\\GitUpdate\\CreationellCaptchaGitPluginUpdater' ) ) {
            new \Creationell\Captcha\GitUpdate\CreationellCaptchaGitPluginUpdater(
                CREATIONELL_CAPTCHA_FILE,
                CREATIONELL_CAPTCHA_VERSION,
                'https://creationell-dev.github.io/creationell-captcha/plugin_creationell-captcha.json'
            );
        }
    },
    5
);

/**
 * Fires after all CreaCaptcha modules are loaded and the public API
 * (`creationell_captcha_*`-functions, REST routes, integration hooks) is
 * ready. Third-party code can safely call into the plugin from this point.
 *
 * @since 0.1.0
 */
do_action( 'creationell_captcha_loaded' );
