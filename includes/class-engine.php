<?php
/**
 * Captcha engine — challenge creation, solution verification, replay guard.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha;

use Creationell\Captcha\Vendor\AltchaOrg\Altcha\Algorithm\Argon2id;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\Algorithm\DeriveKeyInterface;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\Algorithm\Pbkdf2;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\Altcha;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\Challenge;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\ChallengeParameters;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\CreateChallengeOptions;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\Payload;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\Solution;
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\VerifySolutionOptions;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Wraps the bundled ALTCHA library for the WordPress plugin.
 */
class Engine {

    /**
     * Option-name prefix of the single-use replay markers claimed by verify().
     *
     * Deliberately plain options, not transients — see claim_replay_marker()
     * for why the transient pair could not be made atomic.
     *
     * Public because two routines outside the engine have to find these rows
     * as well (E4a): the deactivation sweep in includes/lifecycle.php and the
     * unconditional removal in uninstall.php. Both used to carry their own copy
     * of the literal; a rename here would have left their rows behind.
     */
    public const REPLAY_PREFIX = 'creationell_captcha_used_';

    /**
     * Transient-name prefix of the "image-code stage passed" markers that the
     * `/code-verify` handler writes (see includes/code-challenge.php).
     */
    private const CODE_PASS_PREFIX = 'creationell_captcha_ccpass_';

    /**
     * Key inside `challenge.parameters.data` that marks a challenge as
     * "issued for the under-attack gate only".
     *
     * Written by the `/challenge` handler (includes/rest.php) whenever a valid
     * `ctx` token suppressed the image-code stage, read by verify() below.
     * Deliberately a shared constant and not the same string typed twice: a
     * typo on either side would turn the rule into a silent no-op that nothing
     * on the interstitial path would notice.
     */
    public const UA_GATE_PARAM = 'uagate';

    /**
     * Cron hook that sweeps expired replay markers out of the options table.
     */
    public const CLEANUP_HOOK = 'creationell_captcha_cleanup_replay_markers';

    /**
     * Seconds between two replay-marker sweeps while markers still exist.
     */
    private const CLEANUP_INTERVAL = 900;

    /**
     * Difficulty presets per algorithm: PoW cost + counter range [min, max].
     *
     * Erstkalibrierung (Spec §7) — bei Bedarf nach dem DDEV-Solve-Zeit-Test
     * an dieser einen Stelle nachjustieren.
     *
     * These values are also the reference point for the incoming-payload caps
     * in params_within_caps(): the plugin never issues anything above them.
     */
    private const PRESETS = [
        'pbkdf2'   => [
            'low'    => [ 'cost' => 3000,  'min' => 5,  'max' => 30  ],
            'medium' => [ 'cost' => 6000,  'min' => 10, 'max' => 60  ],
            'high'   => [ 'cost' => 15000, 'min' => 20, 'max' => 120 ],
        ],
        'argon2id' => [
            'low'    => [ 'cost' => 1, 'min' => 5,  'max' => 40 ],
            'medium' => [ 'cost' => 2, 'min' => 10, 'max' => 80 ],
            'high'   => [ 'cost' => 3, 'min' => 20, 'max' => 160 ],
        ],
    ];

    /**
     * Builds a fresh challenge as a JSON-serialisable array.
     *
     * @return array<string, mixed>
     */
    public function create_challenge(): array {
        $settings   = creationell_captcha_get_settings();
        $algo_key   = $this->algorithm_key();
        $difficulty = $this->difficulty_key( $settings );
        $preset     = self::PRESETS[ $algo_key ][ $difficulty ];

        $expiry = (int) ( $settings['challenge_expiry'] ?? 300 );

        $args = [
            'algorithm' => $this->algorithm(),
            'cost'      => $preset['cost'],
            'counter'   => random_int( $preset['min'], $preset['max'] ),
            'expiresAt' => time() + $expiry,
        ];

        if ( 'argon2id' === $algo_key ) {
            $memory_mib         = (int) ( $settings['argon2id_memory'] ?? 32 );
            $memory_mib         = max( 8, min( 256, $memory_mib ) );
            $args['memoryCost'] = $memory_mib * 1024; // Library expects KiB.
        }

        $challenge = $this->altcha()->createChallenge( new CreateChallengeOptions( ...$args ) );

        return $challenge->toArray();
    }

    /**
     * Transient key of the "image-code stage passed" marker for a challenge.
     *
     * The marker is keyed by the challenge SIGNATURE, and that signature
     * covers `parameters.data.ccode` (the ALTCHA library signs the canonical
     * JSON of the whole parameter set). Two consequences, and they are the
     * reason this binding exists:
     *
     *  - a code token cannot be re-paired with a different challenge (CM-8) —
     *    changing `data.ccode` invalidates the signature, and the signature is
     *    mandatory since prepare_payload();
     *  - a payload that never passed the image-code stage has no marker at all
     *    (CM-1) — omitting the JSON key `code` on `/code-verify` no longer
     *    produces anything the form path accepts.
     *
     * @param string $signature The `challenge.signature` of the payload.
     * @return string Transient name (never empty).
     */
    public static function code_pass_key( string $signature ): string {
        return self::CODE_PASS_PREFIX . hash( 'sha256', $signature );
    }

    /**
     * Verifies a base64-encoded ALTCHA payload and enforces single use.
     *
     * @param string $payload_b64       The base64 payload from the `altcha` form field.
     * @param bool   $under_attack_gate Whether the CALLER is the under-attack
     *                                  interstitial gate. Only that one call
     *                                  site (UnderAttack::run()) passes true;
     *                                  it LIFTS the uagate rule rather than
     *                                  requiring the marker — the gate accepts
     *                                  an ordinary challenge just as well, and
     *                                  deliberately so (see below). Default
     *                                  false — every form path keeps rejecting
     *                                  a marked challenge.
     */
    public function verify( string $payload_b64, bool $under_attack_gate = false ): bool {
        $prepared = $this->prepare_payload( $payload_b64, 'verify' );
        if ( null === $prepared ) {
            return false;
        }

        $signature = $prepared['signature'];

        // FU-1, the rest of BK-4/CM-4: a challenge that `/challenge` issued
        // under ctx suppression carries parameters.data.uagate. That is the one
        // case in which the plugin knowingly hands out a PoW WITHOUT the
        // image-code stage its configuration asks for — the interstitial widget
        // is display="invisible" and could not show a code modal, so a code
        // stage there would deadlock the gate. Such a challenge is therefore
        // worth exactly what the interstitial needs it for and nothing else.
        //
        // What this closes is the REDEMPTION, not the acquisition: one GET of a
        // 503 page still yields one code-stage-free challenge (see the ctx
        // issuer in includes/helpers.php for why that stays open). It can no
        // longer be spent as an `altcha` field at a protected form.
        //
        // Why an attacker cannot get out of it:
        //  - the marker sits INSIDE the signed challenge parameters. Removing
        //    or rewriting it does not make it "not present", it makes the
        //    payload unverifiable: the signature is mandatory since CM-2
        //    (prepare_payload) and covers the canonical JSON of the whole
        //    parameter set including `data`, so a stripped payload dies in
        //    run_verify_solution() a few lines below;
        //  - the check reads the SAME decoded array the signature is verified
        //    against, so no re-encoding can make the two disagree;
        //  - the exemption is decided by the caller, never by the request. No
        //    header, field or query parameter reaches $under_attack_gate.
        //
        // Fail-closed: the default is false, so every call site that is not the
        // gate (form integrations, interceptor, template tag) rejects.
        //
        // m8, so the rule is not read as narrower than it is: the relation is
        // one-directional. A MARKED challenge is redeemable ONLY at the gate;
        // the gate is NOT restricted to marked challenges. It accepts an
        // ordinary one too, and it has to: the marker only exists when a valid
        // `ctx` reached `/challenge`. A ctx that expired, was already spent or
        // never arrived yields an ordinary challenge, and requiring the marker
        // here would turn every one of those into a dead end for the visitor
        // (the interstitial widget is invisible; it cannot show him anything
        // else). Nothing is given away by that: the proof-of-work is the same
        // one, and the marked variant is the WEAKER of the two — it is the one
        // that skipped the image-code stage.
        if ( isset( $prepared['params']['data'][ self::UA_GATE_PARAM ] ) && ! $under_attack_gate ) {
            creationell_captcha_log( 'verify: under-attack-only challenge presented outside the gate — rejected.' );
            return false;
        }

        // Modul 15 bypass guard, rebuilt for Wurzel 3.1 (CM-1/CM-8): a
        // challenge that carried an image-code token in parameters.data.ccode
        // is only worth anything once that code was actually solved.
        //
        // The old guard rejected every ccode payload outright and relied on
        // `/code-verify` handing out a freshly minted, ccode-free payload
        // instead — which is exactly the CM-5 amplifier (the server solved a
        // PoW for the client). `/code-verify` no longer mints; it records a
        // marker bound to this challenge's signature. No marker means the code
        // stage was skipped or the token belonged to another challenge.
        $code_pass_key = null;
        if ( isset( $prepared['params']['data']['ccode'] ) ) {
            $code_pass_key = self::code_pass_key( $signature );
            if ( false === get_transient( $code_pass_key ) ) {
                return false;
            }
        }

        if ( ! $this->run_verify_solution( $prepared, 'verify' ) ) {
            return false;
        }

        if ( ! $this->claim_replay_marker( $signature, $this->replay_marker_lifetime( $prepared['params'] ) ) ) {
            return false;
        }

        // The payload is burned now; the code-stage marker has done its job
        // and must not linger for the rest of its TTL.
        if ( null !== $code_pass_key ) {
            delete_transient( $code_pass_key );
        }

        return true;
    }

    /**
     * Verifies a base64 ALTCHA payload structurally — same signature
     * requirement and same derive-key caps as `verify()`, but without the
     * single-use replay claim and without the code-stage rule.
     *
     * Used by the code-challenge verify endpoint (Modul 15), which must not
     * consume the incoming payload: the user may retry after a wrong code,
     * and the one and only single-use consumption happens in `verify()` when
     * the form is finally submitted.
     *
     * @param string $payload_b64 The base64 payload from the widget.
     */
    public function verify_structural( string $payload_b64 ): bool {
        $prepared = $this->prepare_payload( $payload_b64, 'verify_structural' );
        if ( null === $prepared ) {
            return false;
        }

        return $this->run_verify_solution( $prepared, 'verify_structural' );
    }

    /**
     * Decodes a base64 ALTCHA payload and enforces everything that has to hold
     * BEFORE the vendor library is allowed to derive a single key.
     *
     * @param string $payload_b64 Base64 payload from the client.
     * @param string $context     Short label for the debug log.
     * @return array{params: array<string, mixed>, signature: string, counter: int, derived_key: string}|null
     *                            Prepared payload parts, or null when the payload must be rejected.
     */
    private function prepare_payload( string $payload_b64, string $context ): ?array {
        $decoded = base64_decode( $payload_b64, true );
        if ( false === $decoded ) {
            return null;
        }

        $data = json_decode( $decoded, true );
        if ( ! is_array( $data ) || ! isset( $data['challenge'], $data['solution'] ) ) {
            return null;
        }
        if ( ! is_array( $data['challenge'] ) || ! is_array( $data['solution'] ) ) {
            return null;
        }

        $params_raw = $data['challenge']['parameters'] ?? null;
        if ( ! is_array( $params_raw ) ) {
            return null;
        }

        // CM-2 (Wurzel 3.1): the challenge signature is the only thing that
        // binds cost, memoryCost, keyLength, nonce, salt, expiresAt and
        // data.ccode to THIS server.
        //
        // Up to altcha-org/altcha v2.0.2 the vendor library checked it only
        // when it was present and otherwise walked straight into the full
        // re-derivation path with client-chosen parameters — that was the
        // finding. Since v2.0.3 the library rejects a missing signature itself
        // (lib/altcha-org/altcha/src/Altcha.php, verifySolution(), block
        // "Verify challenge signature"), and it does so before deriving.
        //
        // The guard stays regardless, for two reasons that outlive the version
        // bump: the library only runs that block when an HMAC signature secret
        // is configured — with none set it skips straight to derivation, which
        // is exactly what the fail-closed branch below catches — and a
        // dependency update must never be able to silently remove a security
        // property of this plugin. Defence in depth, not redundancy by
        // accident. Measured in Modul 28; see the note in
        // tests/test-engine-signature-caps.php on what this means for the
        // proof power of that suite.
        $signature = isset( $data['challenge']['signature'] ) && is_string( $data['challenge']['signature'] )
            ? $data['challenge']['signature']
            : '';
        if ( '' === $signature ) {
            return null;
        }

        // Fail-closed: with an empty HMAC secret the library would verify every
        // signature against the empty key, i.e. anyone who knows the install
        // has no secret can forge one. Never "accept without signature" — a
        // broken install must reject, not wave everything through.
        if ( '' === creationell_captcha_get_hmac_secret() ) {
            creationell_captcha_log( $context . ': HMAC signature secret missing — rejecting fail-closed.' );
            return null;
        }

        $counter_raw = $data['solution']['counter'] ?? 0;
        // Non-numeric counters are mapped to -1 so the cap check below rejects
        // them; the library would silently cast them to 0 and derive anyway.
        $counter = is_numeric( $counter_raw ) ? (int) $counter_raw : -1;

        $derived_key = isset( $data['solution']['derivedKey'] ) && is_string( $data['solution']['derivedKey'] )
            ? $data['solution']['derivedKey']
            : '';

        if ( ! $this->params_within_caps( $params_raw, $counter, $context ) ) {
            return null;
        }

        return [
            'params'      => $params_raw,
            'signature'   => $signature,
            'counter'     => $counter,
            'derived_key' => $derived_key,
        ];
    }

    /**
     * Server-side ceiling for the derive-key work an INCOMING payload may ask
     * for (CM-6, Wurzel 3.1).
     *
     * `Pbkdf2::deriveKey()` clamps `cost` only downwards (`max(1, $cost)`) and
     * `Argon2id::deriveKey()` does the same with `memoryCost` — an anonymous
     * POST could therefore request `cost: 200000000` or `memoryCost: 2000000`
     * and bind a PHP worker inside a native C call that `max_execution_time`
     * cannot interrupt. The caps are derived from what the plugin itself ever
     * issues (self::PRESETS) plus headroom, so no legitimate payload can hit
     * them; every value is filterable for installs with custom presets.
     *
     * Parameter extraction mirrors `ChallengeParameters::fromArray()`
     * one-to-one (same `is_int()` checks, same defaults) — otherwise a value
     * this method waves through could reach the library as something else.
     *
     * @param array<string, mixed> $params_raw Raw `challenge.parameters` from the payload.
     * @param int                  $counter    Counter of the submitted solution.
     * @param string               $context    Short label for the debug log.
     */
    private function params_within_caps( array $params_raw, int $counter, string $context ): bool {
        $algorithm   = isset( $params_raw['algorithm'] ) && is_string( $params_raw['algorithm'] )
            ? strtoupper( $params_raw['algorithm'] )
            : '';
        // algorithm_for_name() maps everything that is not ARGON2ID to PBKDF2,
        // so the cap selection has to use exactly the same rule.
        $is_argon2id = 'ARGON2ID' === $algorithm;

        $cost       = isset( $params_raw['cost'] ) && is_int( $params_raw['cost'] ) ? $params_raw['cost'] : 0;
        $key_length = isset( $params_raw['keyLength'] ) && is_int( $params_raw['keyLength'] ) ? $params_raw['keyLength'] : 32;
        // Same fallback as Argon2id::deriveKey() when memoryCost is absent.
        $memory_cost = isset( $params_raw['memoryCost'] ) && is_int( $params_raw['memoryCost'] ) ? $params_raw['memoryCost'] : 32768;

        /**
         * Filters the maximum accepted PBKDF2 iteration count (`cost`) of an
         * incoming ALTCHA payload. Payloads above the cap are rejected before
         * any key derivation runs.
         *
         * The highest value the plugin itself issues is 15000 (preset `high`);
         * the default cap leaves headroom for challenges issued before a
         * settings change.
         *
         * @since 1.1.0
         * @param int $max Maximum PBKDF2 iterations. Default 20000.
         */
        $max_cost = (int) apply_filters( 'creationell_captcha_max_derive_cost', 20000 );

        /**
         * Filters the maximum accepted Argon2id time cost (`cost`, opslimit)
         * of an incoming ALTCHA payload. Payloads above the cap are rejected
         * before any key derivation runs.
         *
         * The highest value the plugin itself issues is 3 (preset `high`).
         *
         * @since 1.1.0
         * @param int $max Maximum Argon2id time cost. Default 5.
         */
        $max_time_cost = (int) apply_filters( 'creationell_captcha_max_derive_time_cost', 5 );

        /**
         * Filters the maximum accepted Argon2id memory cost (`memoryCost`, in
         * KiB) of an incoming ALTCHA payload. Payloads above the cap are
         * rejected before any key derivation runs — an uncapped value turns a
         * single anonymous POST into a multi-gigabyte allocation.
         *
         * The highest value the plugin itself issues is 256 * 1024 KiB
         * (`argon2id_memory` is clamped to 256 MiB in create_challenge()).
         *
         * @since 1.1.0
         * @param int $max Maximum Argon2id memory cost in KiB. Default 262144.
         */
        $max_memory_cost = (int) apply_filters( 'creationell_captcha_max_derive_memory_cost', 262144 );

        /**
         * Filters the maximum accepted counter of a submitted ALTCHA solution.
         * Payloads above the cap are rejected before any key derivation runs.
         *
         * The highest counter the plugin itself issues is 160 (Argon2id preset
         * `high`).
         *
         * @since 1.1.0
         * @param int $max Maximum solution counter. Default 1000.
         */
        $max_counter = (int) apply_filters( 'creationell_captcha_max_solution_counter', 1000 );

        /**
         * Filters the maximum accepted derived-key length (`keyLength`, in
         * bytes) of an incoming ALTCHA payload.
         *
         * PBKDF2 work scales with `ceil(keyLength / 32) * cost`, so an
         * uncapped keyLength re-opens the cost cap above by another route.
         * The plugin only ever issues the library default of 32 bytes.
         *
         * @since 1.1.0
         * @param int $max Maximum derived-key length in bytes. Default 64.
         */
        $max_key_length = (int) apply_filters( 'creationell_captcha_max_derive_key_length', 64 );

        if ( $counter < 0 || $counter > $max_counter ) {
            creationell_captcha_log( $context . ': solution counter out of range — rejected.' );
            return false;
        }

        if ( $key_length > $max_key_length ) {
            creationell_captcha_log( $context . ': keyLength above cap — rejected.' );
            return false;
        }

        if ( $is_argon2id ) {
            if ( $cost > $max_time_cost ) {
                creationell_captcha_log( $context . ': Argon2id time cost above cap — rejected.' );
                return false;
            }
            if ( $memory_cost > $max_memory_cost ) {
                creationell_captcha_log( $context . ': Argon2id memory cost above cap — rejected.' );
                return false;
            }

            return true;
        }

        if ( $cost > $max_cost ) {
            creationell_captcha_log( $context . ': PBKDF2 cost above cap — rejected.' );
            return false;
        }

        return true;
    }

    /**
     * Hands a prepared payload to the vendor library.
     *
     * @param array{params: array<string, mixed>, signature: string, counter: int, derived_key: string} $prepared Prepared payload parts.
     * @param string                                                                                   $context  Short label for the debug log.
     */
    private function run_verify_solution( array $prepared, string $context ): bool {
        try {
            $challenge = new Challenge(
                ChallengeParameters::fromArray( $prepared['params'] ),
                $prepared['signature']
            );
            $solution  = new Solution( $prepared['counter'], $prepared['derived_key'] );

            $result = $this->altcha()->verifySolution( new VerifySolutionOptions(
                payload: new Payload( $challenge, $solution ),
                algorithm: $this->algorithm_for_name( $challenge->parameters->algorithm ),
            ) );
        } catch ( \Throwable $e ) {
            creationell_captcha_log( $context . ' error: ' . $e->getMessage() );
            return false;
        }

        return $result->verified;
    }

    /**
     * How long the single-use marker of a just-verified payload has to stay
     * around — namely for exactly as long as that payload can still be redeemed.
     *
     * Until 1.1.0 this was the CURRENT `challenge_expiry` setting, which is not
     * the same thing: the redeemable lifetime of a payload is fixed when the
     * challenge is issued and travels with it as `expiresAt`. Lowering the
     * setting — the settings range is 60–3600 s and the help text explicitly
     * recommends short values — therefore handed every challenge issued before
     * the change a marker that dies BEFORE the challenge does. In that gap the
     * same payload verifies again, as often as the client likes, until
     * `expiresAt` is finally reached. That is the CM-9 guarantee ("one PoW =
     * one submission") leaking out through a side door.
     *
     * Why reading `expiresAt` out of the payload is safe (and not a new
     * attacker-controlled criterion):
     *
     *  - the value is part of the SIGNED challenge parameters, and the caller
     *    reaches this method only after run_verify_solution() has checked that
     *    signature against this site's HMAC secret. A signature is mandatory
     *    since CM-2 (prepare_payload), and the empty-secret case fails closed
     *    there as well;
     *  - the extraction mirrors `ChallengeParameters::fromArray()` one-to-one
     *    (`isset()` + `is_int()`, see lib/altcha-org/altcha/src/ChallengeParameters.php),
     *    so this method reads exactly the value the signature was verified
     *    against. Anything the library would normalise differently — a string,
     *    a float, a missing key — changes the canonical JSON and thus kills the
     *    signature one step earlier;
     *  - inflating the number is therefore not "a longer marker", it is an
     *    unverifiable payload. And a longer marker would only ever REDUCE what
     *    an attacker can do.
     *
     * @param array<string, mixed> $params Raw, signature-checked `challenge.parameters`.
     * @return int Seconds the marker has to stay around (at least 60).
     */
    private function replay_marker_lifetime( array $params ): int {
        $expires_at = isset( $params['expiresAt'] ) && is_int( $params['expiresAt'] )
            ? $params['expiresAt']
            : 0;

        if ( $expires_at > 0 ) {
            // `+ 1` because the two comparisons do not share a boundary: the
            // library treats a challenge as expired only once
            // `time() > expiresAt` (Altcha::verifySolution), i.e. it still
            // verifies AT expiresAt, while the sweep drops a marker already at
            // `option_value <= time()`. Without the extra second the very last
            // redeemable second of a challenge would stand unguarded.
            $lifetime = $expires_at - time() + 1;
        } else {
            // A challenge without `expiresAt` cannot come from this plugin —
            // create_challenge() always sets it, and a payload that drops the
            // key does not survive the signature check above. Kept as a
            // fail-safe fallback, and deliberately the pre-1.1.0 value: if this
            // branch is ever reached, the marker is no shorter than it used to be.
            $lifetime = (int) ( creationell_captcha_get_settings()['challenge_expiry'] ?? 300 );
        }

        // No upper cap on purpose. `expiresAt` is signed by this site, so its
        // size is this site's own `challenge_expiry` and nothing an attacker
        // picks; a cap below it would re-open exactly the window this method
        // closes. The floor is the one the pre-1.1.0 code had, and it also
        // covers a payload redeemed in the last seconds of its window.
        return max( 60, $lifetime );
    }

    /**
     * Claims the single-use replay marker for a challenge signature. Returns
     * true for exactly one caller, false for every other.
     *
     * @param string $signature The `challenge.signature` of the verified payload.
     * @param int    $expiry    Seconds the marker has to stay around.
     */
    private function claim_replay_marker( string $signature, int $expiry ): bool {
        global $wpdb;

        $option_name = self::REPLAY_PREFIX . hash( 'sha256', $signature );

        // CM-9 (Wurzel 3.1): the previous get_transient()/set_transient() pair
        // was a documented TOCTOU — two identical submits arriving in parallel
        // both read "unused" and both wrote the marker, so both passed.
        //
        // WordPress' own add_option() does NOT close that window either: it
        // first reads the option (wp-includes/option.php, "Make sure the option
        // doesn't already exist") and then runs
        // `INSERT … ON DUPLICATE KEY UPDATE`, so two racers can both come back
        // true.
        //
        // A single INSERT IGNORE has no read in front of it: the winner is
        // picked by the UNIQUE index on wp_options.option_name inside the
        // database engine. The first statement inserts a row (1 affected row),
        // every later statement for the same option_name is ignored (0 affected
        // rows). A DB error yields false, which we also treat as "already
        // claimed" — fail-closed, a marker we cannot write must not let the
        // payload through.
        //
        // autoload 'off' keeps these short-lived rows out of alloptions.
        $inserted = $wpdb->query(
            $wpdb->prepare(
                'INSERT IGNORE INTO %i (`option_name`, `option_value`, `autoload`) VALUES (%s, %s, %s)',
                $wpdb->options,
                $option_name,
                (string) ( time() + $expiry ),
                'off'
            )
        );

        if ( 1 !== (int) $inserted ) {
            return false;
        }

        $this->schedule_replay_cleanup( $expiry );

        return true;
    }

    /**
     * Makes sure the replay markers written above get swept again.
     *
     * Unlike transients, plain options never expire on their own — so the
     * sweep is their ONLY cleanup path and must not be optional.
     *
     * @param int $expiry Lifetime of the marker that was just claimed.
     */
    private function schedule_replay_cleanup( int $expiry ): void {
        $next = wp_next_scheduled( self::CLEANUP_HOOK );

        if ( false === $next ) {
            wp_schedule_single_event( time() + $expiry + 60, self::CLEANUP_HOOK );
            return;
        }

        // WP-Cron is not a scheduler, it is a piggyback on incoming requests:
        // with DISABLE_WP_CRON and no system cron the event above never fires
        // and the markers would pile up in wp_options forever. If the slot is
        // badly overdue, do the sweep inline instead of waiting for a runner
        // that does not exist.
        if ( $next < time() - HOUR_IN_SECONDS ) {
            wp_unschedule_event( $next, self::CLEANUP_HOOK );
            self::cleanup_replay_markers();
        }
    }

    /**
     * Deletes replay markers whose lifetime has run out and re-arms itself
     * while markers are still around. Registered on self::CLEANUP_HOOK at the
     * bottom of this file.
     */
    public static function cleanup_replay_markers(): void {
        global $wpdb;

        $like = $wpdb->esc_like( self::REPLAY_PREFIX ) . '%';

        $wpdb->query(
            $wpdb->prepare(
                'DELETE FROM %i WHERE `option_name` LIKE %s AND CAST(`option_value` AS UNSIGNED) <= %d',
                $wpdb->options,
                $like,
                time()
            )
        );

        $remaining = (int) $wpdb->get_var(
            $wpdb->prepare(
                'SELECT COUNT(*) FROM %i WHERE `option_name` LIKE %s',
                $wpdb->options,
                $like
            )
        );

        if ( $remaining > 0 && false === wp_next_scheduled( self::CLEANUP_HOOK ) ) {
            wp_schedule_single_event( time() + self::CLEANUP_INTERVAL, self::CLEANUP_HOOK );
        }
    }

    /**
     * The derive-key algorithm instance for the configured algorithm.
     */
    private function algorithm(): DeriveKeyInterface {
        return 'argon2id' === $this->algorithm_key() ? new Argon2id() : new Pbkdf2();
    }

    /**
     * Effective algorithm key — falls back to pbkdf2 when argon2id is
     * selected but ext-sodium is unavailable.
     */
    private function algorithm_key(): string {
        $settings = creationell_captcha_get_settings();
        $selected = ( 'argon2id' === ( $settings['algorithm'] ?? 'pbkdf2' ) ) ? 'argon2id' : 'pbkdf2';

        if ( 'argon2id' === $selected && ! creationell_captcha_sodium_available() ) {
            creationell_captcha_log( 'Argon2id selected but ext-sodium missing — falling back to PBKDF2.' );
            return 'pbkdf2';
        }

        return $selected;
    }

    /**
     * Maps a challenge algorithm name to a derive-key instance.
     */
    private function algorithm_for_name( string $name ): DeriveKeyInterface {
        return 'ARGON2ID' === strtoupper( $name ) ? new Argon2id() : new Pbkdf2();
    }

    /**
     * Normalises the configured difficulty.
     *
     * @param array<string, mixed> $settings Plugin settings.
     */
    private function difficulty_key( array $settings ): string {
        $difficulty = (string) ( $settings['difficulty'] ?? 'medium' );

        return in_array( $difficulty, [ 'low', 'medium', 'high' ], true ) ? $difficulty : 'medium';
    }

    /**
     * Builds the underlying ALTCHA object with both HMAC secrets.
     */
    private function altcha(): Altcha {
        return new Altcha(
            creationell_captcha_get_hmac_secret(),
            creationell_captcha_get_hmac_key_secret()
        );
    }
}

// The replay markers claimed in Engine::verify() are plain options: they do
// not expire by themselves the way transients do, so this sweep is their only
// cleanup path. Registered at file scope because the handler has to exist for
// every request that may run WP-Cron, not just for requests that verify.
add_action( Engine::CLEANUP_HOOK, [ Engine::class, 'cleanup_replay_markers' ] );
