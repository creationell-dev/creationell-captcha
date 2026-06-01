<?php
/**
 * Reusable WP-CLI command for a single list-type setting.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

namespace Creationell\Captcha\CLI;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

use WP_CLI;

/**
 * Manages one list-type setting — IP block/allow list, UA block list or the
 * interceptor path list. The same class backs the blocklist, allowlist,
 * ua-blocklist and paths command namespaces.
 */
class List_Command {

    /**
     * The list setting key this instance manages.
     */
    private string $key;

    /**
     * Validation type: 'ip' (IP/CIDR), 'action' (action-slug charset),
     * 'cookie' (name=value), or 'text' (plain).
     */
    private string $validation;

    /**
     * @param string $key        The list setting key.
     * @param string $validation 'ip' (IP/CIDR), 'action' (action slug),
     *                           'cookie' (name=value), or 'text' (plain).
     */
    public function __construct( string $key, string $validation = 'text' ) {
        $this->key        = $key;
        $this->validation = $validation;
    }

    /**
     * Adds one or more entries to the list.
     *
     * ## OPTIONS
     *
     * <entry>...
     * : One or more entries to add.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist add 203.0.113.4 203.0.113.0/24
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function add( $args, $assoc_args ): void {
        $list  = $this->current();
        $added = 0;

        foreach ( $args as $raw ) {
            $entry = $this->normalise( (string) $raw );
            if ( null === $entry ) {
                WP_CLI::warning( sprintf( '„%s" ist kein gültiger Eintrag — übersprungen.', $raw ) );
                continue;
            }
            if ( in_array( $entry, $list, true ) ) {
                WP_CLI::log( sprintf( '„%s" ist bereits enthalten.', $entry ) );
                continue;
            }
            if ( count( $list ) >= 50 ) {
                WP_CLI::warning( 'Die Liste ist voll (maximal 50 Einträge) — weitere Einträge wurden nicht hinzugefügt.' );
                break;
            }
            $list[] = $entry;
            ++$added;
        }

        if ( $added > 0 ) {
            $this->save( $list );
        }
        WP_CLI::success( sprintf( '%d Eintrag/Einträge hinzugefügt.', $added ) );
    }

    /**
     * Removes one or more entries from the list.
     *
     * ## OPTIONS
     *
     * <entry>...
     * : One or more entries to remove.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist remove 203.0.113.4
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function remove( $args, $assoc_args ): void {
        $list    = $this->current();
        $removed = 0;

        foreach ( $args as $raw ) {
            $entry = trim( (string) $raw );
            $index = array_search( $entry, $list, true );
            if ( false === $index ) {
                WP_CLI::log( sprintf( '„%s" war nicht in der Liste.', $entry ) );
                continue;
            }
            unset( $list[ $index ] );
            ++$removed;
        }

        if ( $removed > 0 ) {
            $this->save( array_values( $list ) );
        }
        WP_CLI::success( sprintf( '%d Eintrag/Einträge entfernt.', $removed ) );
    }

    /**
     * Prints the current list entries.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : Output format (table, json, yaml, csv).
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist list
     *
     * @subcommand list
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function list_entries( $args, $assoc_args ): void {
        $format = $assoc_args['format'] ?? 'table';

        $rows = [];
        foreach ( $this->current() as $entry ) {
            $rows[] = [ 'eintrag' => $entry ];
        }

        if ( empty( $rows ) ) {
            WP_CLI::log( 'Die Liste ist leer.' );
            return;
        }

        \WP_CLI\Utils\format_items( $format, $rows, [ 'eintrag' ] );
    }

    /**
     * Empties the list.
     *
     * ## OPTIONS
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp creacaptcha blocklist clear --yes
     *
     * @param array<int, string>    $args       Positional arguments.
     * @param array<string, string> $assoc_args Associative arguments.
     */
    public function clear( $args, $assoc_args ): void {
        WP_CLI::confirm( 'Die gesamte Liste leeren?', $assoc_args );
        $this->save( [] );
        WP_CLI::success( 'Liste geleert.' );
    }

    /**
     * The current list value.
     *
     * @return array<int, string>
     */
    private function current(): array {
        $settings = creationell_captcha_get_settings();
        $list     = $settings[ $this->key ] ?? [];

        return is_array( $list ) ? array_values( array_map( 'strval', $list ) ) : [];
    }

    /**
     * Writes the list back through the settings sanitiser.
     *
     * @param array<int, string> $list The new list.
     */
    private function save( array $list ): void {
        $settings               = creationell_captcha_get_settings();
        $settings[ $this->key ] = $list;
        update_option( 'creationell_captcha_settings', creationell_captcha_sanitize_settings( $settings ) );
    }

    /**
     * Validates and normalises one entry; returns null when invalid.
     *
     * @param string $raw Raw entry value.
     */
    private function normalise( string $raw ): ?string {
        $entry = trim( $raw );
        if ( '' === $entry || strlen( $entry ) > 255 ) {
            return null;
        }

        switch ( $this->validation ) {
            case 'ip':
                return $this->is_ip_or_cidr( $entry ) ? $entry : null;
            case 'action':
                return creationell_captcha_validate_action_pattern( $entry );
            case 'cookie':
                return creationell_captcha_validate_cookie_entry( $entry );
            case 'text':
            default:
                return $entry;
        }
    }

    /**
     * Whether the value is a valid IP address or CIDR range.
     *
     * @param string $value Candidate value.
     */
    private function is_ip_or_cidr( string $value ): bool {
        if ( false !== filter_var( $value, FILTER_VALIDATE_IP ) ) {
            return true;
        }
        if ( ! str_contains( $value, '/' ) ) {
            return false;
        }

        [ $ip, $bits ] = explode( '/', $value, 2 );
        if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) || ! ctype_digit( $bits ) ) {
            return false;
        }

        $max = ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) ? 128 : 32;

        return (int) $bits >= 0 && (int) $bits <= $max;
    }
}
