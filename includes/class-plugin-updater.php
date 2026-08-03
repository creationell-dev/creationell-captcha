<?php
/**
 * CreaCaptcha Plugin Updater – GitHub Self-Hosted Updates
 *
 * Adapted from the "JPKCom Plugin Updater" class, authored and externally
 * maintained by Jean Pierre Kolb (jpk@jpkc.com) across several of his
 * open-source WordPress-plugin projects (originally vendored from
 * `jpkcom-post-filter/includes/class-plugin-updater.php`). When porting
 * updates or bug-fixes upstream/downstream, treat the version in this
 * file as a downstream copy of that shared codebase.
 *
 * Plugin-local changes vs. the shared upstream:
 * - Namespace renamed `JPKComPostFilterGitUpdate` → `Creationell\Captcha\GitUpdate`
 * - Class renamed `JPKComGitPluginUpdater` → `CreationellCaptchaGitPluginUpdater`
 * - Contributors entries include `display_name` (WP core expects it in the
 *   plugin-information popup; fix pending upstream port)
 * - no_update entries include `new_version`/`package`/`tested`/`requires_php`
 *   (WP-CLI reads new_version in `wp plugin list`; fix pending upstream port)
 * - Security audit Modul 27 (all worth porting upstream, LK-1 … LK-7):
 *   the verified download is handed to the installer instead of being thrown
 *   away and fetched a second time; a missing/malformed checksum aborts the
 *   update instead of skipping the gate; package URLs must be https; the
 *   package is matched to this plugin by identity, not by a slug substring;
 *   failed manifest fetches are negatively cached; the manifest is size- and
 *   schema-checked before it is cached AND again after it is read back from
 *   the cache (W3-14: the transient outlives the plugin update that
 *   introduced the check); contributor URLs are validated.
 *   `sprintf()` calls no longer pass `values:` as a named argument (that is an
 *   ArgumentCountError at runtime, not a syntax error), and the manifest
 *   fields that reach a sanitiser which is *not* type-safe are bounded to a
 *   string first (`manifest_string()`): `array_map()` over a missing
 *   `requires_plugins`, `trim()` over non-string `tags` entries, in
 *   `plugin_info()` additionally sections / readme_html / slug / author /
 *   author_profile / homepage / license_uri, and in `check_update()` the icon
 *   URL of both the update and the no_update entry. The remaining
 *   manifest-fed calls are covered by one of three mechanisms: the sanitiser
 *   itself (`sanitize_text_field()`, `wp_http_validate_url()`,
 *   `sanitize_key()` all return ''/false for array and object), an
 *   `is_string()` test at the call site, or `validate_manifest()`, which
 *   rejects the whole manifest when `version`, `download_url` or
 *   `checksum_sha256` is not a usable string — that third one is what covers
 *   `version_compare( $remote->version )` in `check_update()`, whose first
 *   parameter is string-typed (W3-13; the list used to name only the first
 *   two). Audited call by call on 2026-07-30; re-audit after every upstream
 *   merge.
 *
 * Both renames are necessary to avoid `Cannot redeclare class` fatals
 * when more than one of Jean Pierre's plugins (each carrying its own
 * vendored copy of this updater) is active on the same WordPress install.
 * Everything else in this file should stay byte-identical with the
 * upstream to keep cross-project diffs minimal.
 *
 * --- Original upstream description follows ---
 *
 * This class provides a secure, self-hosted update mechanism for WordPress plugins
 * hosted on GitHub. It integrates with the WordPress plugin update system and provides
 * comprehensive security features including:
 *
 * - SHA256 checksum verification of downloaded packages
 * - URL validation and sanitization of all remote data
 * - Race condition prevention for manifest fetching
 * - Comprehensive error logging in WP_DEBUG mode
 * - Transient caching with 24-hour TTL, negative caching of failed fetches
 *
 * Security Features:
 * - All URLs are validated using wp_http_validate_url() before use; the
 *   package URL must additionally be https
 * - All manifest data is sanitized before display
 * - The bytes that were hashed are the bytes that get installed: the verified
 *   temp file is returned to WP_Upgrader::download_package() instead of being
 *   discarded
 * - A missing or malformed checksum aborts the update (fail closed)
 * - Failed verifications prevent installation and log errors
 *
 * Namespace: Creationell\Captcha\GitUpdate (renamed from JPKComPostFilterGitUpdate)
 * PHP Version: 8.3+
 * WordPress Version: 6.8+
 *
 * @author Jean Pierre Kolb <jpk@jpkc.com>
 * @since 1.0.0 Initial release with GitHub integration
 */

declare(strict_types=1);

namespace Creationell\Captcha\GitUpdate;

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

/**
 * Class CreationellCaptchaGitPluginUpdater
 *
 * Handles plugin updates from a GitHub-hosted JSON manifest.
 * Downstream rename of `JPKComGitPluginUpdater` (Jean Pierre Kolb,
 * shared across his plugin projects — see the file-level docblock for
 * the rename rationale).
 *
 * @package Creationell\Captcha\GitUpdate
 * @author  Jean Pierre Kolb <jpk@jpkc.com>
 */
final class CreationellCaptchaGitPluginUpdater {

    /**
     * Largest manifest body that is accepted, in bytes.
     *
     * The decoded manifest is cached in `wp_options` for 24 hours, so its size
     * is the site's problem, not the host's. The live manifest measured 180 KB
     * on 2026-07-30 (README-derived `readme_html` is the bulk of it); 1 MiB is
     * roughly five times that and only has to bound the transient, not track
     * it closely. Raise it here if the README ever grows past that.
     */
    private const MAX_MANIFEST_BYTES = 1048576;

    /** @var int Maximum nesting depth accepted from the manifest JSON. */
    private const MANIFEST_JSON_DEPTH = 32;

    /** @var int How long a failed manifest fetch is remembered, in seconds. */
    private const FETCH_FAILURE_TTL = 300;

    /** @var string Plugin slug (directory name) */
    private string $plugin_slug;

    /** @var string Path to main plugin file */
    private string $plugin_file;

    /** @var string Current plugin version */
    private string $current_version;

    /** @var string Remote manifest URL */
    private string $manifest_url;

    /** @var string Cache key for transient */
    private string $cache_key;

    /** @var bool Whether caching is enabled */
    private bool $cache_enabled = true;

    /**
     * Constructor
     *
     * @param string $plugin_file      Absolute path to the main plugin file (__FILE__).
     * @param string $current_version  Current plugin version.
     * @param string $manifest_url     Full URL to the remote JSON manifest.
     */
    public function __construct( string $plugin_file, string $current_version, string $manifest_url ) {
        global $wp_version;

        // Environment check
        if ( version_compare( version1: PHP_VERSION, version2: '8.3', operator: '<' ) || version_compare( version1: $wp_version, version2: '6.8', operator: '<' ) ) {
            return;
        }

        // Security: Validate and sanitize manifest URL
        $manifest_url = esc_url_raw( $manifest_url );
        if ( ! wp_http_validate_url( $manifest_url ) ) {
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( sprintf(
                    'CreaCaptcha Plugin Updater: Invalid manifest URL provided: %s',
                    $manifest_url
                ) );
            }
            return; // Invalid URL, abort initialization
        }

        $this->plugin_file     = $plugin_file;
        $this->plugin_slug     = dirname( path: plugin_basename( $plugin_file ) );
        $this->current_version = $current_version;
        $this->manifest_url    = $manifest_url;
        $this->cache_key       = 'creationell_captcha_git_update_' . md5( string: $this->plugin_slug );

        // Hook into WordPress update system
        add_filter( 'plugins_api', [$this, 'plugin_info'], 20, 3 );
        add_filter( 'site_transient_update_plugins', [$this, 'check_update'] );
        add_action( 'upgrader_process_complete', [$this, 'clear_cache'], 10, 2 );
        // 4 accepted args: $hook_extra carries the plugin basename WP core is
        // downloading for — the only exact package↔plugin criterion available
        // (LK-4). It exists since WP 5.5; this plugin requires 6.9.
        add_filter( 'upgrader_pre_download', [$this, 'verify_download_checksum'], 10, 4 );
        // Note: 'plugins_api_result' filter is not a standard WordPress filter, keeping for backward compatibility
        // add_filter( 'plugins_api_result', [$this, 'plugin_info'], 20, 3 );

    }

    /**
     * Fetch and decode the remote manifest file.
     *
     * Uses a locking mechanism to prevent race conditions when multiple requests
     * try to fetch the manifest simultaneously.
     *
     * @return ?object Decoded manifest or null on failure.
     */
    private function get_remote_manifest(): ?object {
        $remote = get_transient( $this->cache_key );

        // W3-14: Der Transient ist NICHT vertrauenswürdiger als die Antwort,
        // aus der er stammt. Er hält 24 Stunden und überlebt damit das Update
        // des Plugins selbst: eine Installation, die von 1.0.x auf 1.1.0 geht,
        // liest hier bis zu einen Tag lang einen Wert, den eine Fassung ohne
        // validate_manifest() geschrieben hat. Ein Array in `version` wäre dann
        // ein TypeError in version_compare() auf JEDER wp-admin-Seite. Deshalb
        // läuft der gecachte Wert durch dieselbe Prüfung wie der frisch geholte;
        // besteht er sie nicht, wird er verworfen und der Abruf wiederholt.
        if ( false !== $remote ) {
            $remote = $this->validate_manifest( $remote );
            if ( null === $remote ) {
                delete_transient( $this->cache_key );
                $remote = false;
            }
        }

        if ( false === $remote || ! $this->cache_enabled ) {
            // A failed fetch used to leave no trace, so the next call tried
            // again immediately — and the 15-second timeout below is paid by
            // the cron worker AND by every wp-admin page load that renders the
            // update badge (LK-5). Remember the failure for a few minutes.
            if ( $this->cache_enabled && get_transient( $this->failure_key() ) ) {
                return null;
            }

            // Race condition prevention: Check if another request is already fetching
            $lock_key = $this->cache_key . '_lock';
            if ( get_transient( $lock_key ) ) {
                // Another request is fetching, return null to avoid duplicate API calls
                return null;
            }

            // Acquire lock for 30 seconds
            set_transient( $lock_key, true, 30 );

            $response = wp_safe_remote_get( $this->manifest_url, [
                'timeout' => 15,
                'headers' => ['Accept' => 'application/json'],
            ] );

            // Release lock
            delete_transient( $lock_key );

            // Error handling with logging
            if ( is_wp_error( $response ) ) {
                if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                    error_log( sprintf(
                        'CreaCaptcha Plugin Updater: Failed to fetch manifest from %s - Error: %s',
                        $this->manifest_url,
                        $response->get_error_message()
                    ) );
                }
                $this->remember_fetch_failure();
                return null;
            }

            $response_code = wp_remote_retrieve_response_code( $response );
            if ( $response_code !== 200 ) {
                if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                    error_log( sprintf(
                        'CreaCaptcha Plugin Updater: Invalid response code %d from %s',
                        $response_code,
                        $this->manifest_url
                    ) );
                }
                $this->remember_fetch_failure();
                return null;
            }

            // Bound the input before decoding it: whatever comes back is cached
            // in wp_options for 24 hours, and `readme_html` alone can carry
            // megabytes if the source is compromised (LK-6).
            $body = (string) wp_remote_retrieve_body( $response );
            if ( strlen( $body ) > self::MAX_MANIFEST_BYTES ) {
                if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                    error_log( sprintf(
                        'CreaCaptcha Plugin Updater: Manifest too large (%d bytes, limit %d) at %s',
                        strlen( $body ),
                        self::MAX_MANIFEST_BYTES,
                        $this->manifest_url
                    ) );
                }
                $this->remember_fetch_failure();
                return null;
            }

            $remote = json_decode( json: $body, associative: false, depth: self::MANIFEST_JSON_DEPTH );
            if ( json_last_error() !== JSON_ERROR_NONE ) {
                if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                    error_log( sprintf(
                        'CreaCaptcha Plugin Updater: JSON decode error: %s',
                        json_last_error_msg()
                    ) );
                }
                $this->remember_fetch_failure();
                return null;
            }

            $remote = $this->validate_manifest( $remote );
            if ( null === $remote ) {
                $this->remember_fetch_failure();
                return null;
            }

            set_transient( $this->cache_key, $remote, DAY_IN_SECONDS );
        }

        return is_object( value: $remote ) ? $remote : null;
    }

    /**
     * Transient key under which a failed manifest fetch is remembered.
     */
    private function failure_key(): string {
        return $this->cache_key . '_fail';
    }

    /**
     * Remembers a failed manifest fetch so the next call does not repeat it.
     *
     * The window is deliberately short: a manifest host that is down for a
     * minute must not hide an update for a day. The cost of the miss is one
     * delayed update check, the cost of not having it is a 15-second stall on
     * every admin page load while the host is unreachable (LK-5).
     */
    private function remember_fetch_failure(): void {
        if ( $this->cache_enabled ) {
            set_transient( $this->failure_key(), 1, self::FETCH_FAILURE_TTL );
        }
    }

    /**
     * Structural check of a decoded manifest.
     *
     * Only the three fields the updater *acts* on are validated — version
     * (drives the update decision), download_url (becomes the package URL) and
     * checksum_sha256 (is the gate). Every other field keeps whatever type the
     * JSON carried and is dealt with at the point of use — which for a field
     * that ends up in a string sink means `manifest_string()` first, because
     * the WordPress sanitisers are *not* uniformly type-safe (see there). A
     * manifest that fails any of these is discarded whole: a half-trusted
     * manifest is worse than none, and in particular a present-but-malformed
     * checksum must never degrade into the “no checksum” branch (LK-2/LK-6).
     *
     * @param mixed $remote Decoded manifest.
     * @return ?object The manifest, or null when it does not match the schema.
     */
    private function validate_manifest( mixed $remote ): ?object {
        $reject = static function ( string $why ): ?object {
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'CreaCaptcha Plugin Updater: Manifest rejected — ' . $why );
            }
            return null;
        };

        if ( ! is_object( value: $remote ) ) {
            return $reject( 'not a JSON object' );
        }

        if ( isset( $remote->version )
            && ( ! is_string( value: $remote->version )
                || 1 !== preg_match( '/^[0-9A-Za-z][0-9A-Za-z._\-+]{0,31}$/', $remote->version ) ) ) {
            return $reject( 'unusable version field' );
        }

        if ( isset( $remote->download_url )
            && ( ! is_string( value: $remote->download_url ) || strlen( $remote->download_url ) > 2048 ) ) {
            return $reject( 'unusable download_url field' );
        }

        if ( isset( $remote->checksum_sha256 )
            && ( ! is_string( value: $remote->checksum_sha256 )
                || 1 !== preg_match( '/^[0-9a-fA-F]{64}$/', trim( $remote->checksum_sha256 ) ) ) ) {
            return $reject( 'checksum_sha256 is not a SHA-256 hex digest' );
        }

        return $remote;
    }

    /**
     * A manifest field as a string, or the fallback when the manifest carried
     * something else (array, object, number, bool, null).
     *
     * Why this exists rather than “the sanitiser will handle it”: the
     * WordPress sanitisers disagree about non-strings, and the ones this class
     * uses land on both sides. Measured against WP 6.9 / PHP 8.3:
     *
     * - `sanitize_text_field()` is safe — `_sanitize_text_fields()`
     *   (wp-includes/formatting.php:5634) returns '' for array and object.
     * - `esc_url_raw()` is not: `esc_url()` (formatting.php:4483-4487) only
     *   short-circuits on `'' === $url` and then calls `ltrim( $url )` →
     *   TypeError for array *and* object.
     * - `sanitize_title()` is not: it reaches `preg_match()` inside
     *   `remove_accents()` (formatting.php:1612) → TypeError.
     * - `trim()` is not, for either.
     * - `wp_kses_post()` fatals on an object (`preg_replace()` in
     *   `wp_kses_no_null()`, kses.php:1939) but not on an array: every step of
     *   the chain (`preg_replace()`, `str_replace()`,
     *   `preg_replace_callback()`) accepts an array subject and returns an
     *   array, so the value comes back AS AN ARRAY — element by element
     *   filtered, but never turned into the string the caller expects.
     *   (W3-12: this line used to read “it returns one, unescaped”, which
     *   suggests the content passes unfiltered. The defect is the TYPE, not
     *   the escaping.)
     *
     * So a manifest with e.g. `"homepage": ["x"]` would white-screen the
     * “View details” modal, and `"icons": {"default": ["x"]}` would do it on
     * every wp-admin page load via `check_update()`. `validate_manifest()`
     * bounds only the three fields the updater acts on (see there); this is
     * where the rest is bounded (LK-6).
     *
     * @param mixed  $value    Raw value from the manifest.
     * @param string $fallback Value to use when $value is not a string.
     */
    private function manifest_string( mixed $value, string $fallback = '' ): string {
        return is_string( value: $value ) ? $value : $fallback;
    }

    /**
     * Whether a URL is usable as a package/download source: valid per
     * WordPress' own rules *and* https.
     *
     * `wp_http_validate_url()` accepts plain http, and the file behind this URL
     * is unpacked into wp-content/plugins and executed as PHP on the next
     * request — a downgrade to http is not something the manifest gets to
     * choose (LK-3).
     */
    private function is_https_url( string $url ): bool {
        if ( '' === $url || ! wp_http_validate_url( $url ) ) {
            return false;
        }

        $scheme = wp_parse_url( $url, PHP_URL_SCHEME );

        return is_string( value: $scheme ) && 'https' === strtolower( $scheme );
    }

    /**
     * Provide detailed plugin info in the “View Details” modal.
     *
     * @param mixed  $result Default response.
     * @param string $action Current action.
     * @param object $args   API request arguments.
     * @return mixed
     */
    public function plugin_info( mixed $result, string $action, object $args ): mixed {
        if ( $action !== 'plugin_information' || empty( $args->slug ) || $args->slug !== $this->plugin_slug ) {
            return $result;
        }

        $remote = $this->get_remote_manifest();
        if ( ! $remote ) {
            return $result;
        }

        // `! empty()` used to be the only guard here, and it lets everything
        // truthy through — `"sections":{"description":["x"]}` reached
        // `trim( array )`, i.e. a TypeError, i.e. a blank “View details” modal.
        // Non-string sections are dropped instead (LK-6).
        $sections = [];
        foreach ( ['description','installation','changelog','faq'] as $key ) {
            $section = trim( $this->manifest_string( $remote->sections->$key ?? null ) );
            if ( '' !== $section ) {
                $sections[$key] = wp_kses_post( $section );
            }
        }

        $readme_html = $this->manifest_string( $remote->readme_html ?? null );
        if ( '' !== $readme_html ) {
            $sections['readme'] = wp_kses_post( $readme_html );
        }

        $info = new \stdClass();
        $info->name             = sanitize_text_field( $remote->name ?? '' );
        $info->display_name     = sanitize_text_field( $remote->display_name ?? ( $remote->name ?? '' ) );
        // sanitize_title()/wp_kses_post()/esc_url_raw() all fatal on a
        // non-string; sanitize_text_field() does not. Hence manifest_string()
        // on exactly the former (LK-6).
        $info->slug             = sanitize_title( $this->manifest_string( $remote->slug ?? null, $this->plugin_slug ) );
        $info->version          = sanitize_text_field( $remote->version ?? $this->current_version );
        $info->author           = wp_kses_post( $this->manifest_string( $remote->author ?? null ) );
        $info->author_profile   = esc_url_raw( $this->manifest_string( $remote->author_profile ?? null ) );

        $contributors = $remote->contributors ?? [];

        if ( is_object( value: $contributors ) ) {
            $contributors = (array) $contributors;
        } elseif ( is_string( value: $contributors ) ) {
            $contributors = [$contributors];
        }

        $wp_contributors = [];
        foreach ( $contributors as $key => $value ) {
            if ( is_string( value: $value ) ) {
                $wp_contributors[$value] = [
                    'display_name' => sanitize_text_field( $value ),
                    'profile'      => $this->default_profile_url( $value ),
                    'avatar'       => $this->default_avatar_url( $value ),
                ];
            } elseif ( is_array( value: $value ) || is_object( value: $value ) ) {
                $value = (array) $value;
                $wp_contributors[$key] = [
                    // `??` only catches null/missing; an empty-string display_name falls through to WP core's own username fallback.
                    'display_name' => sanitize_text_field( $value['display_name'] ?? $key ),
                    // Everything else from the manifest that becomes a URL runs
                    // through wp_http_validate_url() — these two did not, and
                    // they end up as href/src in the admin's browser (LK-7).
                    // Anything that is not a valid http(s) URL falls back to the
                    // wordpress.org default rather than being passed through.
                    'profile'      => $this->manifest_url_or_default( $value['profile'] ?? null, $this->default_profile_url( (string) $key ) ),
                    'avatar'       => $this->manifest_url_or_default( $value['avatar'] ?? null, $this->default_avatar_url( (string) $key ) ),
                ];
            }
        }

        $info->contributors     = $wp_contributors;

        $info->homepage         = esc_url_raw( $this->manifest_string( $remote->homepage ?? null ) );
        // Same https requirement as the package URL in check_update() (LK-3) —
        // this field is what the “Install Update Now” button in the modal uses.
        $info->download_link    = $this->is_https_url( is_string( value: $remote->download_url ?? null ) ? $remote->download_url : '' )
            ? esc_url_raw( $remote->download_url )
            : '';
        $info->requires         = sanitize_text_field( $remote->requires ?? '6.8' );
        $info->tested           = sanitize_text_field( $remote->tested ?? '6.9' );
        $info->requires_php     = sanitize_text_field( $remote->requires_php ?? '8.3' );
        $info->license          = sanitize_text_field( $remote->license ?? 'GPL-2.0+' );
        $info->license_uri      = esc_url_raw( $this->manifest_string( $remote->license_uri ?? null, 'http://www.gnu.org/licenses/gpl-2.0.txt' ) );

        // Both lists come straight from the manifest and are fed to string
        // functions. `trim()`/`sanitize_text_field()` on a nested array or
        // object is a TypeError — i.e. a fatal in the “View details” modal — so
        // only the string entries survive (LK-6).
        $tags = $remote->tags ?? [];
        if ( ! is_array( value: $tags ) ) {
            $tags = [$tags];
        }
        $info->tags             = array_values( array_map( callback: 'sanitize_text_field', array: array_map( callback: 'trim', array: array_filter( $tags, 'is_string' ) ) ) );

        $info->network          = (bool) ( $remote->network ?? false );
        // The `??` used to be evaluated for the is_array() test only, while
        // array_map() then read the raw property again — for a manifest
        // *without* `requires_plugins` that is array_map(…, null): fatal.
        $requires_plugins       = $remote->requires_plugins ?? [];
        $info->requires_plugins = is_array( value: $requires_plugins )
            ? array_values( array_map( callback: 'sanitize_text_field', array: array_filter( $requires_plugins, 'is_string' ) ) )
            : [];
        $info->text_domain      = sanitize_text_field( $remote->text_domain ?? '' );
        $info->domain_path      = sanitize_text_field( $remote->domain_path ?? '' );
        $info->last_updated     = sanitize_text_field( $remote->last_updated ?? '' );
        $info->sections         = $sections;

        // Sanitize banner URLs
        $banners = (array) ( $remote->banners ?? [] );
        $info->banners = [];
        foreach ( $banners as $key => $url ) {
            if ( wp_http_validate_url( $url ) ) {
                $info->banners[ sanitize_key( $key ) ] = esc_url_raw( $url );
            }
        }

        // Sanitize icon URLs
        if ( ! empty( $remote->icons ) ) {
            $icons = (array) $remote->icons;
            $info->icons = [];
            foreach ( $icons as $key => $url ) {
                if ( wp_http_validate_url( $url ) ) {
                    $info->icons[ sanitize_key( $key ) ] = esc_url_raw( $url );
                }
            }
        } elseif ( ! empty( $remote->icon ) && wp_http_validate_url( $remote->icon ) ) {
            $info->icons = [ 'default' => esc_url_raw( $remote->icon ) ];
        }

        return $info;
    }

    /**
     * The wordpress.org profile URL used when the manifest supplies none.
     *
     * `sprintf()`'s second parameter is variadic; passing it as the named
     * argument `values:` (as this file did) is an ArgumentCountError at
     * runtime, not a syntax error — positional only. `rawurlencode()` keeps a
     * manifest-supplied name inside the path segment it belongs to.
     *
     * @param string $username Contributor name from the manifest.
     */
    private function default_profile_url( string $username ): string {
        return sprintf( 'https://profiles.wordpress.org/%s', rawurlencode( $username ) );
    }

    /**
     * The wordpress.org avatar URL used when the manifest supplies none.
     *
     * @param string $username Contributor name from the manifest.
     */
    private function default_avatar_url( string $username ): string {
        return sprintf( 'https://wordpress.org/grav-redirect.php?user=%s&s=36', rawurlencode( $username ) );
    }

    /**
     * Returns a manifest-supplied URL if WordPress considers it a valid
     * http(s) URL, otherwise the given default.
     *
     * @param mixed  $url     Raw value from the manifest.
     * @param string $default Fallback URL built by this class.
     */
    private function manifest_url_or_default( mixed $url, string $default ): string {
        if ( is_string( value: $url ) && '' !== $url && wp_http_validate_url( $url ) ) {
            return esc_url_raw( $url );
        }

        return $default;
    }

    /**
     * Check for available plugin updates.
     *
     * @param object $transient WordPress transient data.
     * @return object
     */
    public function check_update( mixed $transient ): object {

        // Defensive initialisation (WordPress may pass false on first run)
        if ( ! is_object( value: $transient ) ) {
            $transient = new \stdClass();
            $transient->checked  = [];
            $transient->response = [];
        }

        if ( empty( $transient->checked ) ) {
            return $transient;
        }

        $remote = $this->get_remote_manifest();
        if ( ! $remote || empty( $remote->version ) ) {
            return $transient;
        }

        if ( version_compare( version1: $this->current_version, version2: $remote->version, operator: '<' ) ) {
            $plugin_basename = plugin_basename( $this->plugin_file );

            // Validate and sanitize download URL. An update entry without a
            // usable https package URL is worse than no entry at all: WP would
            // offer the update and then fail (or, with a plain-http URL, fetch
            // executable code over a channel anyone on the path can rewrite —
            // LK-3). No usable URL, no update offer.
            $download_url = is_string( value: $remote->download_url ?? null ) ? $remote->download_url : '';
            if ( ! $this->is_https_url( $download_url ) ) {
                if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                    error_log( sprintf(
                        'CreaCaptcha Plugin Updater: Invalid download URL in manifest (https required): %s',
                        $download_url
                    ) );
                }
                return $transient; // Invalid download URL, skip update
            }

            $update               = new \stdClass();
            $update->slug         = $this->plugin_slug;
            $update->new_version  = sanitize_text_field( $remote->version ?? '' );
            $update->package      = esc_url_raw( $download_url );
            $update->tested       = sanitize_text_field( $remote->tested ?? '' );
            $update->requires_php = sanitize_text_field( $remote->requires_php ?? '' );
            $update->plugin       = $plugin_basename;

            // Sanitize icon URL. `??` only skips null/missing, so a manifest
            // with `"icons": {"default": ["x"]}` used to hand an array to
            // esc_url_raw() → ltrim(): TypeError. That runs on the
            // site_transient_update_plugins filter, i.e. on *every* wp-admin
            // page load, not just in the details modal (LK-6).
            $icon_url = $this->manifest_string(
                $remote->icons->default ?? $remote->icon ?? null,
                "https://s.w.org/plugins/geopattern-icon/{$this->plugin_slug}.svg"
            );
            $update->icons = [
                'default' => esc_url_raw( $icon_url )
            ];

            $transient->response[ $plugin_basename ] = $update;
        } else {
            $plugin_basename = plugin_basename( $this->plugin_file );

            // Sanitize icon URL for no_update entry — same non-string trap as
            // in the update branch above, and this is the branch that runs in
            // the steady state (no update pending).
            $icon_url = $this->manifest_string(
                $remote->icons->default ?? $remote->icon ?? null,
                "https://s.w.org/plugins/geopattern-icon/{$this->plugin_slug}.svg"
            );

            $transient->no_update[ $plugin_basename ] = (object) [
                'slug'         => $this->plugin_slug,
                'plugin'       => $plugin_basename,
                'new_version'  => sanitize_text_field( $remote->version ?? $this->current_version ),
                'package'      => '',
                'tested'       => sanitize_text_field( $remote->tested ?? '' ),
                'requires_php' => sanitize_text_field( $remote->requires_php ?? '' ),
                'icons'        => [
                    'default' => esc_url_raw( $icon_url )
                ]
            ];
        }

        return $transient;
    }

    /**
     * Clear cached manifest after a successful update.
     *
     * @param \WP_Upgrader $upgrader WordPress upgrader instance.
     * @param array        $options  Upgrade options.
     */
    public function clear_cache( \WP_Upgrader $upgrader, array $options ): void {
        // Ensure array keys exist before accessing
        if ( $this->cache_enabled
             && isset( $options['action'], $options['type'] )
             && $options['action'] === 'update'
             && $options['type'] === 'plugin' ) {
            delete_transient( $this->cache_key );
            // The negative cache goes with it — after an update the next check
            // should be free to hit the network again (LK-5).
            delete_transient( $this->failure_key() );
        }
    }

    /**
     * Verify the package checksum and hand the verified file to the installer.
     *
     * Runs on `upgrader_pre_download`, i.e. *instead of* WP core's own
     * download: `WP_Upgrader::download_package()` returns the first non-false
     * value this filter produces, unchanged, and only downloads itself when
     * every handler returned false.
     *
     * That is exactly why this method returns the temp file on success. The
     * previous version downloaded the package, hashed it, deleted it and
     * returned `$reply` (false) — so core downloaded a *second* copy and
     * installed that one. The SHA-256 covered a file that was thrown away
     * (LK-1). Now the hashed bytes and the installed bytes are the same file.
     * `WP_Upgrader::run()` deletes it after the install because the path
     * differs from `$options['package']`.
     *
     * Note that core's optional signature verification is not lost here: it
     * only applies to wordpress.org/downloads.wordpress.org/s.w.org
     * (`wp_signature_hosts`), never to the github.com release asset this
     * updater fetches.
     *
     * @param bool|string|\WP_Error $reply      Short-circuit value of the filter (default false).
     * @param string                $package    The package file name or URL.
     * @param \WP_Upgrader          $upgrader   The WP_Upgrader instance.
     * @param array<string, mixed>  $hook_extra Extra arguments from the upgrader; carries
     *                                          `plugin` (the plugin basename) for plugin updates.
     * @return bool|string|\WP_Error The verified package path, the untouched $reply, or a WP_Error.
     */
    public function verify_download_checksum( $reply, string $package, \WP_Upgrader $upgrader, array $hook_extra = [] ) {
        // Another handler on this filter already produced a package; core will
        // use that one and never see ours. Those are not our bytes to vouch
        // for, and re-downloading the URL would say nothing about them.
        if ( false !== $reply ) {
            return $reply;
        }

        $plugin_basename = plugin_basename( $this->plugin_file );

        // Ownership by identity, not by substring: WP core names the plugin it
        // is downloading for in $hook_extra['plugin'] (Plugin_Upgrader::
        // upgrade() and ::bulk_upgrade() both set it). `strpos($package,
        // $slug)` used to pull *any* foreign package whose URL happened to
        // contain our 19-character slug into this gate, where our checksum then
        // blocked that other plugin's update (LK-4).
        $hook_plugin = isset( $hook_extra['plugin'] ) && is_string( value: $hook_extra['plugin'] )
            ? $hook_extra['plugin']
            : '';
        if ( '' !== $hook_plugin && $hook_plugin !== $plugin_basename ) {
            return $reply;
        }

        $remote = $this->get_remote_manifest();

        if ( '' === $hook_plugin ) {
            // No plugin identity from core (Plugin_Upgrader::install() does not
            // set it, e.g. for a manually uploaded ZIP). The only exact
            // criterion left is the manifest's own download URL.
            $manifest_url = ( $remote && isset( $remote->download_url ) && is_string( value: $remote->download_url ) )
                ? esc_url_raw( $remote->download_url )
                : '';
            if ( '' === $manifest_url || $package !== $manifest_url ) {
                return $reply;
            }
        }

        // ---- From here on this download is ours, and it is gated. ----------

        if ( ! $this->is_https_url( $package ) ) {
            $error_msg = __( 'Security verification failed: the update package must be downloaded over HTTPS.', 'creationell-captcha' );
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'CreaCaptcha Plugin Updater: ' . $error_msg . ' URL: ' . $package );
            }

            return new \WP_Error( 'insecure_package_url', $error_msg );
        }

        // Without the manifest there is nothing to verify against. Own error
        // code: “manifest unreachable” and “manifest without checksum” are
        // different problems for whoever reads the message, and the first one
        // is usually temporary (host down, or another request is holding the
        // fetch lock).
        if ( ! $remote ) {
            $error_msg = __( 'Security verification failed: the update manifest could not be loaded, so the package cannot be verified. Please try again later.', 'creationell-captcha' );
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'CreaCaptcha Plugin Updater: ' . $error_msg );
            }

            return new \WP_Error( 'manifest_unavailable', $error_msg );
        }

        // No usable checksum, no installation. This used to `return $reply`
        // with nothing but a WP_DEBUG note, which let a manifest without
        // `checksum_sha256` install an unverified package — a gate that can be
        // switched off from the outside is not a gate (LK-2). The manifest
        // built by .github/public-repo/release.yml always carries the field;
        // if it is missing, something is wrong and stopping is the answer.
        $expected_hash = ( isset( $remote->checksum_sha256 ) && is_string( value: $remote->checksum_sha256 ) )
            ? strtolower( trim( $remote->checksum_sha256 ) )
            : '';
        if ( 1 !== preg_match( '/^[0-9a-f]{64}$/', $expected_hash ) ) {
            $error_msg = __( 'Security verification failed: the update manifest carries no usable SHA-256 checksum for this package.', 'creationell-captcha' );
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'CreaCaptcha Plugin Updater: ' . $error_msg );
            }

            return new \WP_Error( 'checksum_missing', $error_msg );
        }

        // Download package
        $temp_file = download_url( $package );
        if ( is_wp_error( $temp_file ) ) {
            return new \WP_Error(
                'download_failed',
                sprintf(
                    __( 'Download failed: %s', 'creationell-captcha' ),
                    $temp_file->get_error_message()
                )
            );
        }

        // Calculate SHA256 hash
        $calculated_hash = hash_file( 'sha256', $temp_file );

        // Verify checksum (timing-safe).
        if ( ! is_string( value: $calculated_hash ) || ! hash_equals( $expected_hash, $calculated_hash ) ) {
            // Only on the failure path is the file ours to delete — on success
            // the installer takes it over.
            @unlink( $temp_file );

            $error_msg = sprintf(
                /* translators: 1: expected SHA-256 hash, 2: calculated SHA-256 hash */
                __( 'Security verification failed: Plugin checksum mismatch. Expected: %1$s, Got: %2$s', 'creationell-captcha' ),
                $expected_hash,
                is_string( value: $calculated_hash ) ? $calculated_hash : '(hash failed)'
            );

            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'CreaCaptcha Plugin Updater: ' . $error_msg );
            }

            return new \WP_Error( 'checksum_mismatch', $error_msg );
        }

        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            error_log( 'CreaCaptcha Plugin Updater: Checksum verification successful' );
        }

        return $temp_file;
    }
}
