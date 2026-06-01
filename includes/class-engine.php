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
use Creationell\Captcha\Vendor\AltchaOrg\Altcha\SolveChallengeOptions;
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
     * Difficulty presets per algorithm: PoW cost + counter range [min, max].
     *
     * Erstkalibrierung (Spec §7) — bei Bedarf nach dem DDEV-Solve-Zeit-Test
     * an dieser einen Stelle nachjustieren.
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
     * Verifies a base64-encoded ALTCHA payload and enforces single use.
     *
     * @param string $payload_b64 The base64 payload from the `altcha` form field.
     */
    public function verify( string $payload_b64 ): bool {
        $decoded = base64_decode( $payload_b64, true );
        if ( false === $decoded ) {
            return false;
        }

        $data = json_decode( $decoded, true );
        if ( ! is_array( $data ) || ! isset( $data['challenge'], $data['solution'] ) ) {
            return false;
        }
        if ( ! is_array( $data['challenge'] ) || ! is_array( $data['solution'] ) ) {
            return false;
        }

        $params_raw = $data['challenge']['parameters'] ?? null;
        if ( ! is_array( $params_raw ) ) {
            return false;
        }

        // Modul 15 bypass guard: a Challenge that carried a code-challenge
        // token in parameters.data.ccode is only valid AFTER going through
        // /code-verify. The /code-verify handler issues a fresh payload via
        // issue_signed_payload(), which does NOT set data.ccode. Any payload
        // arriving here with data.ccode set has bypassed /code-verify —
        // reject.
        if ( isset( $params_raw['data']['ccode'] ) ) {
            return false;
        }

        try {
            $signature = isset( $data['challenge']['signature'] ) && is_string( $data['challenge']['signature'] )
                ? $data['challenge']['signature']
                : null;

            $challenge = new Challenge( ChallengeParameters::fromArray( $params_raw ), $signature );
            $solution  = new Solution(
                (int) ( $data['solution']['counter'] ?? 0 ),
                (string) ( $data['solution']['derivedKey'] ?? '' )
            );

            $result = $this->altcha()->verifySolution( new VerifySolutionOptions(
                payload: new Payload( $challenge, $solution ),
                algorithm: $this->algorithm_for_name( $challenge->parameters->algorithm ),
            ) );
        } catch ( \Throwable $e ) {
            creationell_captcha_log( 'verify error: ' . $e->getMessage() );
            return false;
        }

        if ( ! $result->verified ) {
            return false;
        }

        // Replay guard — a verified challenge is single-use. The get/set transient
        // pair is not atomic; two identical payloads submitted simultaneously could
        // both pass. Accepted trade-off of the transient-based guard (spec §9).
        if ( null === $signature || '' === $signature ) {
            return false;
        }
        $transient_key = 'creationell_captcha_used_' . hash( 'sha256', $signature );
        if ( false !== get_transient( $transient_key ) ) {
            return false;
        }

        $expiry = (int) ( creationell_captcha_get_settings()['challenge_expiry'] ?? 300 );
        set_transient( $transient_key, 1, $expiry );

        return true;
    }

    /**
     * Verifies a base64 ALTCHA payload structurally — same checks as
     * `verify()` minus the single-use replay guard. Used by the code-
     * challenge verify endpoint (Modul 15), which must not consume the
     * incoming payload because the user may retry on wrong code.
     *
     * NOTE: also skips the `parameters.data.ccode` reject filter — the
     * code-verify handler explicitly EXPECTS that field to be present.
     *
     * @param string $payload_b64 The base64 payload from the widget.
     */
    public function verify_structural( string $payload_b64 ): bool {
        $decoded = base64_decode( $payload_b64, true );
        if ( false === $decoded ) {
            return false;
        }

        $data = json_decode( $decoded, true );
        if ( ! is_array( $data ) || ! isset( $data['challenge'], $data['solution'] ) ) {
            return false;
        }
        if ( ! is_array( $data['challenge'] ) || ! is_array( $data['solution'] ) ) {
            return false;
        }

        $params_raw = $data['challenge']['parameters'] ?? null;
        if ( ! is_array( $params_raw ) ) {
            return false;
        }

        try {
            $signature = isset( $data['challenge']['signature'] ) && is_string( $data['challenge']['signature'] )
                ? $data['challenge']['signature']
                : null;

            $challenge = new Challenge( ChallengeParameters::fromArray( $params_raw ), $signature );
            $solution  = new Solution(
                (int) ( $data['solution']['counter'] ?? 0 ),
                (string) ( $data['solution']['derivedKey'] ?? '' )
            );

            $result = $this->altcha()->verifySolution( new VerifySolutionOptions(
                payload: new Payload( $challenge, $solution ),
                algorithm: $this->algorithm_for_name( $challenge->parameters->algorithm ),
            ) );
        } catch ( \Throwable $e ) {
            creationell_captcha_log( 'verify_structural error: ' . $e->getMessage() );
            return false;
        }

        return $result->verified;
    }

    /**
     * Issues a fresh, server-solved ALTCHA payload — base64 string that
     * `Engine::verify()` will accept exactly once. Used by the code-challenge
     * verify endpoint (Modul 15) to substitute the user's original PoW
     * payload (which carried a data.ccode marker and would be rejected by
     * verify()'s bypass guard) with a clean payload that has no data.ccode.
     *
     * Returns the empty string on internal error (no payload issued).
     */
    public function issue_signed_payload(): string {
        try {
            $challenge_arr = $this->create_challenge();

            $params_raw = $challenge_arr['parameters'] ?? null;
            $signature  = $challenge_arr['signature'] ?? null;
            if ( ! is_array( $params_raw ) || ! is_string( $signature ) ) {
                return '';
            }

            $params    = ChallengeParameters::fromArray( $params_raw );
            $challenge = new Challenge( $params, $signature );
            $algorithm = $this->algorithm_for_name( $params->algorithm );

            $solution = $this->altcha()->solveChallenge(
                new SolveChallengeOptions(
                    challenge: $challenge,
                    algorithm: $algorithm,
                    timeout: 5.0
                )
            );
            if ( null === $solution ) {
                return '';
            }

            $payload = new Payload( $challenge, $solution );
            return $payload->toBase64();
        } catch ( \Throwable $e ) {
            creationell_captcha_log( 'issue_signed_payload error: ' . $e->getMessage() );
            return '';
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
