<?php
/**
 * Argon2id memory budget for the browser (Modul 31).
 *
 * The vendored <altcha-widget> solves an Argon2id challenge with one Web
 * Worker per logical CPU (at most 16, at most 4 when navigator.deviceMemory
 * reports ≤ 4 GB), and every worker reserves the challenge's full
 * `memoryCost`. At 256 MiB per worker a 16-thread desktop asks for 4 GiB.
 * These helpers derive an upper bound for the worker count from a total
 * budget so that workers × memory never exceeds it.
 *
 * The bound is applied in the browser as min( budget workers, widget
 * heuristic ) via `$altcha.defaults` — NOT as a `workers` attribute. The
 * attribute is a fixed count that replaces the widget's heuristic entirely
 * (no cap by CPU count or device memory), so on a 2-core / 4 GB phone it
 * would RAISE memory use (e.g. 48 MiB: 2 × 48 → 10 × 48). Via the defaults
 * store the widget never uses more workers than its own heuristic picks.
 *
 * Kept out of helpers.php on purpose: the engine needs
 * creationell_captcha_argon2id_memory_mib(), and the Level-2 tests load the
 * engine without helpers.php (they stub its functions).
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Argon2id memory per derivation in MiB, clamped to the settings range.
 *
 * The single source for this value: Engine::create_challenge() signs it into
 * the challenge (`memoryCost`), and the worker budget below divides by it. A
 * stored value outside 8–256 (old installs, direct option writes) is clamped
 * the same way in both places.
 */
function creationell_captcha_argon2id_memory_mib(): int {
    $settings = creationell_captcha_get_settings();

    return max( 8, min( 256, (int) ( $settings['argon2id_memory'] ?? 32 ) ) );
}

/**
 * Total browser memory budget for Argon2id in MiB (never negative).
 */
function creationell_captcha_argon2id_memory_budget(): int {
    /**
     * Filters the total memory budget, in MiB, that one visitor's browser may
     * spend on solving an Argon2id challenge.
     *
     * The plugin derives an upper bound for the widget's solver workers as
     * floor( budget / argon2id_memory ), clamped to 1–16; the browser uses
     * the smaller of that bound and the widget's own heuristic (one worker
     * per CPU, at most 4 on devices reporting ≤ 4 GB). At 16 nothing is set.
     * At least one worker is always used — a budget below the memory per
     * worker is therefore exceeded by that one worker. Only affects Argon2id
     * and only the browser; server-side
     * verification is capped separately by
     * `creationell_captcha_max_derive_memory_cost`.
     *
     * @since 1.2.0
     *
     * @param int $budget Budget in MiB. Default 512.
     */
    return max( 0, (int) apply_filters( 'creationell_captcha_argon2id_memory_budget', 512 ) );
}

/**
 * Whether challenges are actually issued with Argon2id — mirrors the
 * engine's fallback to PBKDF2 when ext-sodium is missing.
 */
function creationell_captcha_argon2id_active(): bool {
    $settings = creationell_captcha_get_settings();

    return 'argon2id' === ( $settings['algorithm'] ?? 'pbkdf2' ) && creationell_captcha_sodium_available();
}

/**
 * Upper bound for the widget's Argon2id solver workers from the budget.
 *
 * @return int|null 1–15, or null when no bound is needed (not Argon2id, or
 *                  the budget allows all 16 workers).
 */
function creationell_captcha_argon2id_workers(): ?int {
    if ( ! creationell_captcha_argon2id_active() ) {
        return null;
    }

    $workers = max( 1, min( 16, intdiv( creationell_captcha_argon2id_memory_budget(), creationell_captcha_argon2id_memory_mib() ) ) );

    return 16 === $workers ? null : $workers;
}

/**
 * One-line summary for `wp creacaptcha status`.
 */
function creationell_captcha_argon2id_workers_summary(): string {
    if ( ! creationell_captcha_argon2id_active() ) {
        return '— (Algorithmus PBKDF2)';
    }

    $memory  = creationell_captcha_argon2id_memory_mib();
    $budget  = creationell_captcha_argon2id_memory_budget();
    $workers = creationell_captcha_argon2id_workers();

    if ( null === $workers ) {
        return sprintf( 'Widget-Standard (bis 16 × %d MiB = %d MiB, Budget %d MiB)', $memory, 16 * $memory, $budget );
    }

    return sprintf( 'bis %d × %d MiB = %d MiB (Budget %d MiB)', $workers, $memory, $workers * $memory, $budget );
}

/**
 * Inline JS that registers the Argon2id worker with the widget and, when the
 * budget requires it, caps the solver workers via `$altcha.defaults`.
 *
 * Must run after the widget bundle (which creates `globalThis.$altcha`) and
 * before a widget starts solving. The widget reads `workers` from its
 * defaults store only at solve time and merges the store over its own
 * heuristic, so the value written here — min( budget bound, heuristic ),
 * the heuristic mirrored 1:1 from the vendored bundle — is what it uses.
 * Shared by the form widget (wp_add_inline_script 'after') and the
 * under-attack interstitial (<head>, before the <altcha-widget> element).
 *
 * @return string JS, or '' when Argon2id is not in effect.
 */
function creationell_captcha_argon2id_worker_script(): string {
    if ( ! creationell_captcha_argon2id_active() ) {
        return '';
    }

    $worker_url = add_query_arg( 'ver', CREATIONELL_CAPTCHA_VERSION, CREATIONELL_CAPTCHA_PLUGIN_URL . 'assets/js/altcha-argon2id.worker.js' );

    $js = sprintf(
        'if(window.$altcha&&window.$altcha.algorithms){window.$altcha.algorithms.set("ARGON2ID",function(){return new Worker(%s);});}',
        wp_json_encode( $worker_url )
    );

    $bound = creationell_captcha_argon2id_workers();
    if ( null !== $bound ) {
        // Heuristic as in altcha 3.3.0: hc = hardwareConcurrency || 2;
        // deviceMemory ≤ 4 → min( 4, hc ), else hc.
        $js .= sprintf(
            'if(window.$altcha&&window.$altcha.defaults){var cc_hc=navigator.hardwareConcurrency||2,cc_dm=navigator.deviceMemory||0,cc_h=cc_dm&&cc_dm<=4?Math.min(4,cc_hc):cc_hc;window.$altcha.defaults.set("workers",Math.max(1,Math.min(%d,cc_h)));}',
            $bound
        );
    }

    return $js;
}
