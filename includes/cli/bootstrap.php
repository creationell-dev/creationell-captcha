<?php
/**
 * WP-CLI command registration for CreaCaptcha.
 *
 * Part of the normal include chain, but a no-op outside WP-CLI.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
    return;
}

require_once __DIR__ . '/class-cli-command.php';
require_once __DIR__ . '/class-cli-settings-command.php';
require_once __DIR__ . '/class-cli-list-command.php';
require_once __DIR__ . '/class-cli-log-command.php';
require_once __DIR__ . '/class-cli-cloudflare-command.php';
require_once __DIR__ . '/class-cli-cloudflare-refresh-alias.php';
require_once __DIR__ . '/class-cli-test-bypass-command.php';
require_once __DIR__ . '/class-cli-doctor-command.php';

WP_CLI::add_command( 'creacaptcha', new \Creationell\Captcha\CLI\Command() );
WP_CLI::add_command( 'creacaptcha settings', new \Creationell\Captcha\CLI\Settings_Command() );
WP_CLI::add_command( 'creacaptcha blocklist', new \Creationell\Captcha\CLI\List_Command( 'firewall_ip_block', 'ip' ) );
WP_CLI::add_command( 'creacaptcha allowlist', new \Creationell\Captcha\CLI\List_Command( 'firewall_ip_allow', 'ip' ) );
WP_CLI::add_command( 'creacaptcha ua-blocklist', new \Creationell\Captcha\CLI\List_Command( 'firewall_ua_block', 'text' ) );
WP_CLI::add_command( 'creacaptcha paths', new \Creationell\Captcha\CLI\List_Command( 'interceptor_paths', 'text' ) );
WP_CLI::add_command( 'creacaptcha trusted-proxies', new \Creationell\Captcha\CLI\List_Command( 'firewall_trusted_proxies', 'ip' ) );
WP_CLI::add_command( 'creacaptcha bypass-ua', new \Creationell\Captcha\CLI\List_Command( 'bypass_ua_allow', 'text' ) );
WP_CLI::add_command( 'creacaptcha bypass-cookies', new \Creationell\Captcha\CLI\List_Command( 'bypass_cookies', 'cookie' ) );
WP_CLI::add_command( 'creacaptcha actions', new \Creationell\Captcha\CLI\List_Command( 'interceptor_actions', 'action' ) );
WP_CLI::add_command( 'creacaptcha inject-paths', new \Creationell\Captcha\CLI\List_Command( 'interceptor_inject_paths', 'text' ) );
WP_CLI::add_command( 'creacaptcha watchlist', new \Creationell\Captcha\CLI\List_Command( 'code_challenge_watchlist', 'ip' ) );
WP_CLI::add_command( 'creacaptcha log', new \Creationell\Captcha\CLI\Log_Command() );
WP_CLI::add_command( 'creacaptcha cloudflare', new \Creationell\Captcha\CLI\Cloudflare_Command() );
WP_CLI::add_command( 'creacaptcha refresh-cloudflare-ips', new \Creationell\Captcha\CLI\Cloudflare_Refresh_Alias() );
WP_CLI::add_command( 'creacaptcha test-bypass', new \Creationell\Captcha\CLI\Test_Bypass_Command() );
WP_CLI::add_command( 'creacaptcha doctor', new \Creationell\Captcha\CLI\Doctor_Command() );
