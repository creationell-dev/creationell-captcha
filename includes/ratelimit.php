<?php
/**
 * Rate-limiter bootstrap: registers the rate limiter on `init` at priority 0.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Runs the per-IP rate limiter. Hooked on `init` at priority 0; registered
 * after the firewall so the firewall runs first.
 */
function creationell_captcha_run_rate_limiter(): void {
    ( new \Creationell\Captcha\RateLimiter() )->run();
}
add_action( 'init', 'creationell_captcha_run_rate_limiter', 0 );
