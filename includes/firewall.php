<?php
/**
 * Firewall bootstrap: registers the firewall on `init` at priority 0.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Runs the IP/user-agent firewall. Hooked on `init` at priority 0 so it fires
 * before the rate limiter, the interceptor and any form-processing handler.
 */
function creationell_captcha_run_firewall(): void {
    ( new \Creationell\Captcha\Firewall() )->run();
}
add_action( 'init', 'creationell_captcha_run_firewall', 0 );
