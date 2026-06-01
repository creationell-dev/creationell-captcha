<?php
/**
 * Analytics bootstrap: wires the security-event hooks to the recorder.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Returns the shared analytics recorder instance.
 */
function creationell_captcha_analytics(): \Creationell\Captcha\Analytics {
    static $instance = null;

    if ( null === $instance ) {
        $instance = new \Creationell\Captcha\Analytics();
    }

    return $instance;
}

/**
 * Records a security event of the given type.
 *
 * @param string               $type    The event type.
 * @param array<string, mixed> $context Optional caller-supplied context.
 */
function creationell_captcha_record_event( string $type, array $context = [] ): void {
    creationell_captcha_analytics()->record( $type, $context );
}

// The generic event channel fired by the form and under-attack modules.
add_action( 'creationell_captcha_event', 'creationell_captcha_record_event', 10, 2 );

// The existing module hooks (interceptor, firewall, rate-limiter), mapped to
// the recorder's event types with a fitting context.
add_action(
    'creationell_captcha_interceptor_passed',
    static function (): void {
        creationell_captcha_record_event(
            'verified',
            [
                'action'      => 'interceptor',
                'interceptor' => true,
            ]
        );
    }
);
add_action(
    'creationell_captcha_interceptor_blocked',
    static function (): void {
        creationell_captcha_record_event(
            'failed',
            [
                'action'      => 'interceptor',
                'interceptor' => true,
                'reason'      => __( 'Challenge ungültig oder fehlend', 'creationell-captcha' ),
            ]
        );
    }
);
add_action(
    'creationell_captcha_firewall_blocked',
    static function ( $context = [] ): void {
        creationell_captcha_record_event(
            'firewall',
            [
                'action' => 'firewall',
                'reason' => is_array( $context ) ? (string) ( $context['reason'] ?? '' ) : '',
            ]
        );
    },
    10,
    1
);
add_action(
    'creationell_captcha_ratelimit_exceeded',
    static function (): void {
        creationell_captcha_record_event(
            'ratelimit',
            [
                'action' => 'ratelimit',
                'reason' => __( 'Rate-Limit überschritten', 'creationell-captcha' ),
            ]
        );
    }
);
