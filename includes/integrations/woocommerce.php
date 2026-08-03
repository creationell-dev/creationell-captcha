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
 * `protect_wc_lost_password` (render) and `protect_password_reset` (verify)
 * are independent toggles — see IN-5 below for the resulting split states,
 * surfaced via `wp creacaptcha doctor`.
 *
 * Known, deliberately-scoped gaps (Modul 27 security audit, 2026-07-29):
 *
 * - IN-2 (P0): the WooCommerce Block Checkout (Store API route) never calls
 *   `process_checkout()`, so neither the render hook
 *   (`woocommerce_review_order_before_submit`) nor the verify hook
 *   (`woocommerce_after_checkout_validation`) below ever runs for it — a
 *   Block Checkout is completely unprotected regardless of
 *   `protect_wc_checkout`. Building Store-API protection is explicitly OUT
 *   OF SCOPE here (new functionality, its own module per the audit's Phase-2
 *   plan); `creationell_captcha_wc_uses_block_checkout()` below only detects
 *   the gap so `wp creacaptcha doctor` and the Settings help text can stop
 *   giving a false "protected" impression.
 * - IN-3/IN-4: the classic checkout's account-creation branch and the
 *   standalone My-Account registration form both funnel through
 *   `woocommerce_registration_errors` (fired unconditionally by
 *   `wc_create_new_customer()`) — see the per-request verify cache and the
 *   form-context guard below.
 * - IN-12 (P3, fail-closed): all four render hooks above sit in overridable
 *   WooCommerce templates (`payment.php`, `form-login.php`,
 *   `form-lost-password.php`, `global/form-login.php`), while every verify
 *   runs from core PHP hooks that do not depend on the template at all. A
 *   theme that copies one of these templates and drops the corresponding
 *   `do_action()` call loses the widget but NOT the server-side check —
 *   the form fails closed (no spam bypass) rather than open, but every
 *   submission is then rejected. This is a general theme-customization risk
 *   common to any WooCommerce hook-based extension, not fixable from inside
 *   this plugin; documented here rather than "fixed".
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

/**
 * Whether the currently configured WooCommerce checkout page uses the Block
 * Checkout (the `woocommerce/checkout` block) rather than the classic
 * `[woocommerce_checkout]` shortcode.
 *
 * IN-2: this codebase only ever protects the classic checkout — the render
 * hook (`woocommerce_review_order_before_submit`) and the verify hook
 * (`woocommerce_after_checkout_validation`) both fire exclusively from
 * `WC_Checkout::process_checkout()`, which the Block Checkout's Store API
 * route never calls. This function exists purely to DETECT that gap for
 * `wp creacaptcha doctor` and the Settings help text — it deliberately does
 * NOT attempt to inject the widget or hook the Store API route (out of
 * scope per the audit's Phase-2 plan; that would be new functionality
 * belonging to its own module).
 */
function creationell_captcha_wc_uses_block_checkout(): bool {
    if ( ! class_exists( 'WooCommerce' ) || ! function_exists( 'wc_get_page_id' ) ) {
        return false;
    }

    $page_id = wc_get_page_id( 'checkout' );
    if ( $page_id <= 0 ) {
        return false;
    }

    return has_block( 'woocommerce/checkout', $page_id );
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
 * Per-request cache of the checkout's own verify verdict, keyed by the raw
 * `altcha` payload currently in `$_POST`.
 *
 * IN-3: the classic checkout, when the customer checks "create an
 * account?", posts exactly ONE `altcha` payload but runs it through TWO of
 * our verify hooks within the same request —
 * `creationell_captcha_wc_checkout_verify()` first (inside
 * `WC_Checkout::validate_checkout()`), then
 * `creationell_captcha_wc_registration_verify()` a few lines later (inside
 * `WC_Checkout::process_customer()` → `wc_create_new_customer()`), reading
 * the IDENTICAL `$_POST['altcha']`. The underlying ALTCHA challenge is
 * single-use (`class-engine.php`'s replay-transient marker), so the second
 * check would always find the payload already marked used and fail — an
 * account-creating order could never succeed. Recording the checkout
 * verdict here lets the registration verify reuse it for the same payload
 * instead of re-running the used-marker check a second time.
 *
 * Scoped to this file/request only (`static`, resets every request) — it
 * does not weaken replay protection across requests: a genuinely replayed
 * payload from an EARLIER request still hits the used-marker on its very
 * first check here, because this cache starts empty every time.
 *
 * @param bool|null $set Pass a bool to record the verdict for the current
 *                       raw payload; omit (null, default) to just read a
 *                       previously recorded one.
 * @return bool|null The cached verdict for the current raw payload, or
 *                    `null` if none has been recorded yet this request.
 */
function creationell_captcha_wc_checkout_verify_cache( ?bool $set = null ): ?bool {
    static $verdicts = [];

    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the payload is the token; read-only cache-key lookup, no state change.
    $raw = isset( $_POST['altcha'] ) && is_string( $_POST['altcha'] ) ? wp_unslash( $_POST['altcha'] ) : '';

    if ( null !== $set ) {
        $verdicts[ $raw ] = $set;
        return $set;
    }

    return $verdicts[ $raw ] ?? null;
}

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
        creationell_captcha_wc_checkout_verify_cache( true );
        do_action( 'creationell_captcha_event', 'verified', $context );
        return;
    }

    creationell_captcha_wc_checkout_verify_cache( false );
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
 * Reads a nonce value the way the given WooCommerce field name(s) would,
 * replicating WooCommerce core's own field-name-agnostic fallback: the
 * dedicated field wins if present, otherwise the generic `_wpnonce` field is
 * used. WooCommerce's own nonce checks do not care WHICH field carried the
 * value — only whether the value itself verifies against the action name.
 *
 * Review fix (Fix-Runde 1, IN-4 critical): an earlier version of this guard
 * checked the dedicated field's mere PRESENCE
 * (`isset( $_POST['woocommerce-register-nonce'] )`) as its "genuine form"
 * signal. That was exploitable — WooCommerce itself resolves the nonce
 * VALUE via the same `_wpnonce` fallback implemented here, so an anonymous
 * attacker could read the nonce value off the real registration form's
 * hidden field and resubmit `register=…&email=…&_wpnonce=<value>` while
 * OMITTING the `woocommerce-register-nonce` field. WooCommerce would still
 * accept the nonce via its fallback and create the account, while the old,
 * presence-only guard saw no dedicated field and treated the request as
 * "no form context" — skipping the captcha check entirely. Checking the
 * NONCE VALUE (via `wp_verify_nonce()`) instead of field presence closes
 * this: the fallback is followed identically on both sides, so there is no
 * field-name an attacker can omit to fool this guard while WooCommerce
 * itself still accepts the request.
 *
 * @param array<string, mixed> $source           `$_POST` or `$_REQUEST`.
 * @param string               $dedicated_field  The form's own nonce field name.
 * @param string               $action           The nonce action to verify against.
 */
function creationell_captcha_wc_nonce_verifies( array $source, string $dedicated_field, string $action ): bool {
    $raw = $source[ $dedicated_field ] ?? ( $source['_wpnonce'] ?? '' );
    if ( ! is_string( $raw ) || '' === $raw ) {
        return false;
    }

    return false !== wp_verify_nonce( wp_unslash( $raw ), $action );
}

/**
 * Whether the current `wc_create_new_customer()` call originates from a
 * genuine WooCommerce registration- or checkout-form POST, as opposed to a
 * Store-API, programmatic or CLI call that never had a form (and therefore
 * no `altcha` field) in the first place.
 *
 * IN-4: `wc_create_new_customer()` fires `woocommerce_registration_errors`
 * — the filter this module hooks — UNCONDITIONALLY, including for the
 * Woo Blocks Store API's own account-creation path and for direct
 * programmatic calls (`wp eval`, custom scripts, other plugins). Hard-
 * rejecting those whenever no `altcha` field happens to be present made
 * `wc_create_new_customer()` unusable outside an actual captcha-protected
 * form — the customer was simply never created.
 *
 * Both genuine entry points already verify their OWN nonce, inside
 * WooCommerce core, before ever calling `wc_create_new_customer()` — so
 * independently re-verifying the SAME nonce value/action here (not
 * consuming anything, `wp_verify_nonce()` is read-only) is a safe, precise
 * signal, as long as it replicates WC's exact field-name fallback (see
 * `creationell_captcha_wc_nonce_verifies()` above — a presence-only check
 * was exploitable, see that function's docblock):
 *
 *  - Standalone My-Account registration form:
 *    `WC_Form_Handler::process_registration()` gates on
 *    `isset( $_POST['register'], $_POST['email'] )` plus a valid
 *    `woocommerce-register` nonce (dedicated field
 *    `woocommerce-register-nonce`, falling back to `_wpnonce`) before ever
 *    calling `wc_create_new_customer()`.
 *  - Classic checkout with "Create an account?": `WC_Checkout::process_checkout()`
 *    verifies the `woocommerce-process_checkout` nonce (dedicated field
 *    `woocommerce-process-checkout-nonce`, falling back to `_wpnonce`, read
 *    from `$_REQUEST`) before `validate_checkout()`/`process_customer()`
 *    run — and by the time this filter fires from inside
 *    `process_customer()`, our OWN checkout verify
 *    (`creationell_captcha_wc_checkout_verify()`) has already run too, see
 *    IN-3's cache below.
 *
 * CLI/cron/XML-RPC calls need no explicit exclusion here: none of them ever
 * populate `$_POST`/`$_REQUEST` with a nonce that verifies against either
 * action, so both checks below already resolve to `false` for them without
 * a dedicated SAPI/constant check — one less thing to keep in sync, and it
 * keeps this guard testable by directly setting `$_POST` (see tests/eval/).
 *
 * Deliberately does NOT exclude on `wp_doing_ajax()`: WooCommerce's classic
 * checkout is itself normally submitted via `wc-ajax=checkout`
 * (`WC_AJAX::checkout()`, which defines `DOING_AJAX` itself before
 * dispatch) — excluding AJAX outright would silently re-open IN-3/IN-4 for
 * the majority of real-world checkouts.
 */
function creationell_captcha_wc_registration_form_context(): bool {
    // The Woo Blocks Store API is a REST route — rest_api_loaded() sets this
    // constant in WordPress core before any route dispatches — and posts a
    // JSON body, not classic $_POST fields. Explicitly out of scope here,
    // consistent with IN-2 (no Store-API protection is being added).
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        return false;
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verifying the nonce IS the point of this function; nothing here is used for a security decision beyond "does the CAPTCHA CHECK apply", never as an authorization bypass.
    if ( isset( $_POST['register'], $_POST['email'] )
        && creationell_captcha_wc_nonce_verifies( $_POST, 'woocommerce-register-nonce', 'woocommerce-register' )
    ) {
        return true;
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verifying the nonce IS the point of this function; mirrors WC_Checkout::process_checkout()'s own $_REQUEST-based lookup.
    if ( creationell_captcha_wc_nonce_verifies( $_REQUEST, 'woocommerce-process-checkout-nonce', 'woocommerce-process_checkout' ) ) {
        return true;
    }

    return false;
}

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

    // IN-4: no genuine Woo registration-/checkout-form POST behind this call
    // (Store API, programmatic, CLI/eval) — do not hard-reject it for
    // lacking a captcha it was never shown in the first place.
    if ( ! creationell_captcha_wc_registration_form_context() ) {
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

    // IN-3: reuse the checkout's own verdict for the identical payload when
    // this fires from within an account-creating classic checkout (see
    // creationell_captcha_wc_checkout_verify_cache() above) instead of
    // re-running verify_request() against an already-consumed replay
    // marker. Falls through to a normal, independent verify for the
    // standalone My-Account registration form, where no checkout verify
    // ran in this request at all.
    $cached   = creationell_captcha_wc_checkout_verify_cache();
    $verified = null !== $cached ? $cached : creationell_captcha_verify_request();

    if ( $verified ) {
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
