<?php
/**
 * WooCommerce integration.
 *
 * Protects four WooCommerce forms — Checkout, My-Account login, registration
 * and lost-password — when the master toggle `protect_woocommerce` and the
 * respective sub-toggle are on. Reviews are out of scope: they use the
 * WordPress comment system and are already covered by `protect_comments`.
 *
 * Lost-Password is render-only: WooCommerce submits the lost-password form
 * through WordPress core's `retrieve_password()`, which fires
 * `lostpassword_post`. Our existing core module
 * (`includes/forms/password-reset.php`) hooks that action — adding another
 * verify here would just produce duplicate verification and duplicate events.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Whether any WooCommerce protection applies right now.
 *
 * Shared gate that the per-form predicates `_wc_*_active()` route through —
 * encapsulates the kill-switch, the `class_exists` check and the master
 * toggle so each form predicate just needs to add its own sub-toggle check.
 */
function creationell_captcha_woocommerce_active(): bool {
    if ( creationell_captcha_is_disabled() ) {
        return false;
    }
    if ( ! class_exists( 'WooCommerce' ) ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_woocommerce'] );
}

/* -------------------------------------------------------------------------
 * Checkout
 * -------------------------------------------------------------------------
 */

/**
 * Whether the WooCommerce checkout protection is active.
 */
function creationell_captcha_wc_checkout_active(): bool {
    if ( ! creationell_captcha_woocommerce_active() ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_wc_checkout'] );
}

/**
 * Renders the widget directly before the Place-Order button on the checkout.
 */
function creationell_captcha_wc_checkout_render(): void {
    if ( ! creationell_captcha_wc_checkout_active() ) {
        return;
    }

    /**
     * Filters whether the widget is auto-injected before the WooCommerce
     * Place-Order button. Return `false` to skip rendering — useful when
     * the theme already places the widget elsewhere on the checkout.
     *
     * The checkout has no per-form ID; the second argument is always 0
     * (kept for signature parity with the other autoinject filters).
     *
     * @since 0.23.0
     * @param bool $inject  Whether to inject. Default true.
     * @param int  $form_id Always 0 for the WooCommerce checkout.
     */
    if ( ! apply_filters( 'creationell_captcha_wc_checkout_autoinject', true, 0 ) ) {
        return;
    }

    creationell_captcha_render_widget();
}
add_action( 'woocommerce_review_order_before_submit', 'creationell_captcha_wc_checkout_render' );

/**
 * Verifies the captcha during checkout validation.
 *
 * `woocommerce_after_checkout_validation` fires inside WooCommerce's
 * `process_checkout()` after all other validation has run; adding an error
 * to the passed-through `WP_Error` aborts the order.
 *
 * @param array<string, mixed> $data   Posted checkout data (unused).
 * @param mixed                $errors The checkout `WP_Error` (passed by reference of the object).
 */
function creationell_captcha_wc_checkout_verify( $data, $errors ): void {
    unset( $data );

    if ( ! creationell_captcha_wc_checkout_active() ) {
        return;
    }

    $context = [
        'plugin' => 'WooCommerce',
        'action' => 'wc_checkout',
    ];

    /** This action is documented in includes/rest.php. */
    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        $context['reason'] = $bypass['reason'];
        do_action( 'creationell_captcha_event', 'verified', $context );
        return;
    }

    if ( creationell_captcha_verify_request() ) {
        do_action( 'creationell_captcha_event', 'verified', $context );
        return;
    }

    $context['reason'] = __( 'Challenge ungültig oder fehlend', 'creationell-captcha' );
    do_action( 'creationell_captcha_event', 'failed', $context );
    creationell_captcha_log( 'WooCommerce checkout rejected — captcha verification failed.' );

    if ( $errors instanceof WP_Error ) {
        $errors->add(
            'creationell_captcha_failed',
            __( 'Die Sicherheitsabfrage wurde nicht bestanden.', 'creationell-captcha' )
        );
    }
}
add_action( 'woocommerce_after_checkout_validation', 'creationell_captcha_wc_checkout_verify', 10, 2 );

/* -------------------------------------------------------------------------
 * My-Account Login
 * -------------------------------------------------------------------------
 */

/**
 * Whether the WooCommerce my-account login protection is active.
 */
function creationell_captcha_wc_login_active(): bool {
    if ( ! creationell_captcha_woocommerce_active() ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_wc_login'] );
}

/**
 * Renders the widget at the bottom of the WooCommerce login form.
 */
function creationell_captcha_wc_login_render(): void {
    if ( ! creationell_captcha_wc_login_active() ) {
        return;
    }

    /**
     * Filters whether the widget is auto-injected into the WooCommerce
     * my-account login form. Return `false` to suppress rendering.
     *
     * @since 0.23.0
     * @param bool $inject  Whether to inject. Default true.
     * @param int  $form_id Always 0 for the WooCommerce login form.
     */
    if ( ! apply_filters( 'creationell_captcha_wc_login_autoinject', true, 0 ) ) {
        return;
    }

    creationell_captcha_render_widget();
}
add_action( 'woocommerce_login_form_end', 'creationell_captcha_wc_login_render' );

/**
 * Verifies the captcha on a WooCommerce my-account login submission.
 *
 * Returns a WP_Error to fail the login; otherwise returns the incoming
 * `$validation_error` value unchanged (so other filters can keep working).
 *
 * @param mixed  $validation_error The current validation error (`WP_Error|null|false`).
 * @param string $username         Submitted username (unused).
 * @param string $password         Submitted password (unused).
 * @return mixed
 */
function creationell_captcha_wc_login_verify( $validation_error, $username, $password ) {
    unset( $username, $password );

    if ( ! creationell_captcha_wc_login_active() ) {
        return $validation_error;
    }
    if ( $validation_error instanceof WP_Error && $validation_error->has_errors() ) {
        return $validation_error; // WooCommerce already rejected this.
    }

    $context = [
        'plugin' => 'WooCommerce',
        'action' => 'wc_login',
    ];

    /** This action is documented in includes/rest.php. */
    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        $context['reason'] = $bypass['reason'];
        do_action( 'creationell_captcha_event', 'verified', $context );
        return $validation_error;
    }

    if ( creationell_captcha_verify_request() ) {
        do_action( 'creationell_captcha_event', 'verified', $context );
        return $validation_error;
    }

    $context['reason'] = __( 'Challenge ungültig oder fehlend', 'creationell-captcha' );
    do_action( 'creationell_captcha_event', 'failed', $context );
    creationell_captcha_log( 'WooCommerce login rejected — captcha verification failed.' );

    return new WP_Error(
        'creationell_captcha_failed',
        __( '<strong>Fehler:</strong> Die Sicherheitsabfrage wurde nicht bestanden.', 'creationell-captcha' )
    );
}
add_filter( 'woocommerce_process_login_errors', 'creationell_captcha_wc_login_verify', 10, 3 );

/* -------------------------------------------------------------------------
 * My-Account Registrierung
 * -------------------------------------------------------------------------
 */

/**
 * Whether the WooCommerce registration protection is active.
 */
function creationell_captcha_wc_registration_active(): bool {
    if ( ! creationell_captcha_woocommerce_active() ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_wc_registration'] );
}

/**
 * Renders the widget at the bottom of the WooCommerce registration form.
 */
function creationell_captcha_wc_registration_render(): void {
    if ( ! creationell_captcha_wc_registration_active() ) {
        return;
    }

    /**
     * Filters whether the widget is auto-injected into the WooCommerce
     * my-account registration form. Return `false` to suppress rendering.
     *
     * @since 0.23.0
     * @param bool $inject  Whether to inject. Default true.
     * @param int  $form_id Always 0 for the WooCommerce registration form.
     */
    if ( ! apply_filters( 'creationell_captcha_wc_registration_autoinject', true, 0 ) ) {
        return;
    }

    creationell_captcha_render_widget();
}
add_action( 'woocommerce_register_form', 'creationell_captcha_wc_registration_render' );

/**
 * Verifies the captcha during WooCommerce my-account registration.
 *
 * @param mixed  $errors   The current `WP_Error` carrier from WooCommerce.
 * @param string $username Submitted username (unused).
 * @param string $email    Submitted email (unused).
 * @return mixed
 */
function creationell_captcha_wc_registration_verify( $errors, $username, $email ) {
    unset( $username, $email );

    if ( ! creationell_captcha_wc_registration_active() ) {
        return $errors;
    }

    $context = [
        'plugin' => 'WooCommerce',
        'action' => 'wc_registration',
    ];

    /** This action is documented in includes/rest.php. */
    $bypass = creationell_captcha_request_bypassed();
    if ( false !== $bypass ) {
        $context['reason'] = $bypass['reason'];
        do_action( 'creationell_captcha_event', 'verified', $context );
        return $errors;
    }

    if ( creationell_captcha_verify_request() ) {
        do_action( 'creationell_captcha_event', 'verified', $context );
        return $errors;
    }

    $context['reason'] = __( 'Challenge ungültig oder fehlend', 'creationell-captcha' );
    do_action( 'creationell_captcha_event', 'failed', $context );
    creationell_captcha_log( 'WooCommerce registration rejected — captcha verification failed.' );

    if ( $errors instanceof WP_Error ) {
        $errors->add(
            'creationell_captcha_failed',
            __( '<strong>Fehler:</strong> Die Sicherheitsabfrage wurde nicht bestanden.', 'creationell-captcha' )
        );
    }

    return $errors;
}
add_filter( 'woocommerce_registration_errors', 'creationell_captcha_wc_registration_verify', 10, 3 );

/* -------------------------------------------------------------------------
 * My-Account Lost-Password (render-only)
 * -------------------------------------------------------------------------
 *
 * Server-side verification is provided by the core password-reset module
 * (`includes/forms/password-reset.php`), which hooks `lostpassword_post`.
 * WooCommerce submits the lost-password form through WP-core's
 * `retrieve_password()`, so the existing hook fires for Woo submissions as
 * well. We only add the widget rendering on Woo's template — there is no
 * Woo-specific verify here.
 */

/**
 * Whether the WooCommerce lost-password render is active.
 */
function creationell_captcha_wc_lost_password_active(): bool {
    if ( ! creationell_captcha_woocommerce_active() ) {
        return false;
    }

    return ! empty( creationell_captcha_get_settings()['protect_wc_lost_password'] );
}

/**
 * Renders the widget inside the WooCommerce lost-password form.
 */
function creationell_captcha_wc_lost_password_render(): void {
    if ( ! creationell_captcha_wc_lost_password_active() ) {
        return;
    }

    /**
     * Filters whether the widget is auto-injected into the WooCommerce
     * lost-password form. Return `false` to suppress rendering. Note: the
     * server-side verification on this form is handled by the WordPress
     * core password-reset module — there is no Woo-specific verify here.
     *
     * @since 0.23.0
     * @param bool $inject  Whether to inject. Default true.
     * @param int  $form_id Always 0 for the WooCommerce lost-password form.
     */
    if ( ! apply_filters( 'creationell_captcha_wc_lost_password_autoinject', true, 0 ) ) {
        return;
    }

    creationell_captcha_render_widget();
}
add_action( 'woocommerce_lostpassword_form', 'creationell_captcha_wc_lost_password_render' );
