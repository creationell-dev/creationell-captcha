<?php
/**
 * Under-attack bootstrap: registers the gate on `template_redirect`.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Runs the under-attack interstitial gate for front-end page views. Hooked on
 * `template_redirect` — fires only for front-end requests, so wp-admin,
 * wp-login.php, REST and cron are inherently exempt.
 */
function creationell_captcha_run_under_attack(): void {
    ( new \Creationell\Captcha\UnderAttack() )->run();
}
add_action( 'template_redirect', 'creationell_captcha_run_under_attack' );
