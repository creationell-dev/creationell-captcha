<?php
/**
 * Analytics dashboard — the tabbed "Statistik" submenu page.
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers the "Statistik" submenu page under the CreaCaptcha menu.
 */
function creationell_captcha_register_analytics_page(): void {
    $hook = add_submenu_page(
        'creationell-captcha',
        __( 'Statistik', 'creationell-captcha' ),
        __( 'Statistik', 'creationell-captcha' ),
        'manage_options',
        'creationell-captcha-analytics',
        'creationell_captcha_render_analytics_page'
    );
    creationell_captcha_tabbed_page_hooks( $hook );
}
add_action( 'admin_menu', 'creationell_captcha_register_analytics_page' );

/**
 * Human-readable labels for the seven event types.
 *
 * @return array<string, string>
 */
function creationell_captcha_analytics_labels(): array {
    return [
        'verified'           => __( 'Captcha gelöst', 'creationell-captcha' ),
        'failed'             => __( 'Captcha fehlgeschlagen', 'creationell-captcha' ),
        'firewall'           => __( 'Firewall-Blocks', 'creationell-captcha' ),
        'ratelimit'          => __( 'Rate-Limit-Blocks', 'creationell-captcha' ),
        'underattack'        => __( 'Under-Attack-Abfragen', 'creationell-captcha' ),
        'underattack_passed' => __( 'Under-Attack bestanden', 'creationell-captcha' ),
        'challenge'          => __( 'Challenges ausgestellt', 'creationell-captcha' ),
    ];
}

/**
 * Thematic groups for the overview tab: title, explanation and the member
 * event types with their short in-group labels.
 *
 * Together the groups cover all seven event types exactly once. The long
 * labels from creationell_captcha_analytics_labels() stay untouched for the
 * filter dropdown, CSV export, CLI and history tab.
 *
 * @return array<int, array{title: string, description: string, types: array<string, string>}>
 */
function creationell_captcha_analytics_groups(): array {
    return [
        [
            'title'       => __( 'Formular-Captchas', 'creationell-captcha' ),
            'description' => __( 'Captcha-Prüfungen beim Absenden geschützter Formulare (Kommentare, Login, CF7, Forminator, WPForms, WooCommerce, Interceptor)', 'creationell-captcha' ),
            'types'       => [
                'verified' => __( 'Gelöst', 'creationell-captcha' ),
                'failed'   => __( 'Fehlgeschlagen', 'creationell-captcha' ),
            ],
        ],
        [
            'title'       => __( 'Abgewehrte Zugriffe', 'creationell-captcha' ),
            'description' => __( 'Hart blockierte Anfragen — diese Besucher kamen nicht durch', 'creationell-captcha' ),
            'types'       => [
                'firewall'  => __( 'Firewall-Blocks', 'creationell-captcha' ),
                'ratelimit' => __( 'Rate-Limit-Blocks', 'creationell-captcha' ),
            ],
        ],
        [
            'title'       => __( 'Under-Attack-Modus', 'creationell-captcha' ),
            'description' => __( 'Besucher, denen die Under-Attack-Sicherheitsprüfung gestellt wurde. „Bestanden" zeigt, wie viele Besucher die Prüfung gelöst haben und durchgelassen wurden — die Differenz blieb außen vor (kein JavaScript, Bots) oder hat die Prüfung noch nicht gelöst.', 'creationell-captcha' ),
            'types'       => [
                'underattack'        => __( 'Abfragen gestellt', 'creationell-captcha' ),
                'underattack_passed' => __( 'Bestanden', 'creationell-captcha' ),
            ],
        ],
        [
            'title'       => __( 'Technisch', 'creationell-captcha' ),
            'description' => __( 'Ausgestellte PoW-Aufgaben — der Zähler steigt bei jedem Laden eines Captcha-Widgets und ist daher höher als die Zahl der gelösten Captchas', 'creationell-captcha' ),
            'types'       => [
                'challenge' => __( 'Challenges ausgestellt', 'creationell-captcha' ),
            ],
        ],
    ];
}

/**
 * The three tabs of the analytics page.
 *
 * @return array<string, string> Tab id => visible label.
 */
function creationell_captcha_analytics_tabs(): array {
    return [
        'overview' => __( 'Übersicht', 'creationell-captcha' ),
        'history'  => __( 'Verlauf', 'creationell-captcha' ),
        'events'   => __( 'Ereignisse', 'creationell-captcha' ),
    ];
}

/**
 * Sums the $days most recent day buckets, per event type.
 *
 * Iterates today plus the ($days - 1) preceding days — the same window the
 * 30-day history table walks.
 *
 * @param array<string, array<string, int>> $daily Daily counters keyed by 'Y-m-d'.
 * @param int                               $days  Number of day buckets to sum.
 * @return array<string, int> Event type => sum.
 */
function creationell_captcha_sum_recent_days( array $daily, int $days ): array {
    $totals = array_fill_keys( array_keys( creationell_captcha_analytics_labels() ), 0 );

    for ( $i = 0; $i < $days; $i++ ) {
        $day    = gmdate( 'Y-m-d', time() - $i * 86400 );
        $counts = isset( $daily[ $day ] ) && is_array( $daily[ $day ] ) ? $daily[ $day ] : [];
        foreach ( array_keys( $totals ) as $type ) {
            $totals[ $type ] += isset( $counts[ $type ] ) ? (int) $counts[ $type ] : 0;
        }
    }

    return $totals;
}

/**
 * Sums the $hours most recent hour buckets, per event type.
 *
 * Iterates the current hour plus the ($hours - 1) preceding hours.
 *
 * @param array<string, array<string, int>> $hourly Hourly counters keyed by 'Y-m-d H'.
 * @param int                               $hours  Number of hour buckets to sum.
 * @return array<string, int> Event type => sum.
 */
function creationell_captcha_sum_recent_hours( array $hourly, int $hours ): array {
    $totals = array_fill_keys( array_keys( creationell_captcha_analytics_labels() ), 0 );

    for ( $i = 0; $i < $hours; $i++ ) {
        $hour   = gmdate( 'Y-m-d H', time() - $i * 3600 );
        $counts = isset( $hourly[ $hour ] ) && is_array( $hourly[ $hour ] ) ? $hourly[ $hour ] : [];
        foreach ( array_keys( $totals ) as $type ) {
            $totals[ $type ] += isset( $counts[ $type ] ) ? (int) $counts[ $type ] : 0;
        }
    }

    return $totals;
}

/**
 * Renders the tabbed analytics dashboard page.
 */
function creationell_captcha_render_analytics_page(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $tabs       = creationell_captcha_analytics_tabs();
    $active_tab = creationell_captcha_active_tab( $tabs );
    $base_url   = menu_page_url( 'creationell-captcha-analytics', false );
    ?>
    <div class="wrap creationell-captcha-analytics creationell-captcha-tabbed">
        <h1 class="wp-heading-inline"><?php echo esc_html__( 'CreaCaptcha — Statistik', 'creationell-captcha' ); ?></h1>
        <a href="<?php echo esc_url( add_query_arg( [] ) ); ?>" class="page-title-action"><?php echo esc_html__( '↻ Aktualisieren', 'creationell-captcha' ); ?></a>
        <hr class="wp-header-end">

        <?php creationell_captcha_render_nav_tabs( $tabs, $active_tab, $base_url ); ?>

        <div
            class="creationell-captcha-tab<?php echo 'overview' === $active_tab ? ' is-active' : ''; ?>"
            id="creationell-captcha-tab-overview"
            data-tab="overview"
        >
            <?php creationell_captcha_render_analytics_overview(); ?>
        </div>

        <div
            class="creationell-captcha-tab<?php echo 'history' === $active_tab ? ' is-active' : ''; ?>"
            id="creationell-captcha-tab-history"
            data-tab="history"
        >
            <?php creationell_captcha_render_analytics_history(); ?>
        </div>

        <div
            class="creationell-captcha-tab<?php echo 'events' === $active_tab ? ' is-active' : ''; ?>"
            id="creationell-captcha-tab-events"
            data-tab="events"
        >
            <?php creationell_captcha_render_analytics_events(); ?>
        </div>
    </div>
    <?php
}

/**
 * Renders the "Übersicht" tab: four 24-hour KPI tiles and one four-window
 * comparison table per thematic group.
 */
function creationell_captcha_render_analytics_overview(): void {
    $analytics = creationell_captcha_analytics();
    $daily     = $analytics->get_daily_counts();
    $hourly    = $analytics->get_hourly_counts();

    $windows = [
        [ 'label' => __( '24 Stunden', 'creationell-captcha' ), 'totals' => creationell_captcha_sum_recent_hours( $hourly, 24 ) ],
        [ 'label' => __( '7 Tage', 'creationell-captcha' ),     'totals' => creationell_captcha_sum_recent_days( $daily, 7 ) ],
        [ 'label' => __( '30 Tage', 'creationell-captcha' ),    'totals' => creationell_captcha_sum_recent_days( $daily, 30 ) ],
        [ 'label' => __( '90 Tage', 'creationell-captcha' ),    'totals' => creationell_captcha_sum_recent_days( $daily, 90 ) ],
    ];

    // Render the defined groups, then catch any event type that exists in the
    // central labels registry but is not assigned to a group — a future type
    // must never silently disappear from the overview.
    $groups        = creationell_captcha_analytics_groups();
    $grouped_types = [];
    foreach ( $groups as $group ) {
        $grouped_types = array_merge( $grouped_types, array_keys( $group['types'] ) );
    }
    $ungrouped = array_diff_key( creationell_captcha_analytics_labels(), array_flip( $grouped_types ) );
    if ( ! empty( $ungrouped ) ) {
        $groups[] = [
            'title'       => __( 'Weitere Ereignisse', 'creationell-captcha' ),
            'description' => __( 'Ereignistypen, die noch keiner Gruppe zugeordnet sind', 'creationell-captcha' ),
            'types'       => $ungrouped,
        ];
    }

    // The KPI tiles summarise the 24-hour window (the first window). "Abgewehrt"
    // counts hard blocks only (firewall + rate limit) — under-attack prompts are
    // a gate, not a block, and get their own asked/passed tile instead.
    $h24  = $windows[0]['totals'];
    $kpis = [
        [
            'value'    => number_format_i18n( (int) $h24['verified'] ),
            'label'    => __( 'Captcha gelöst (24 h)', 'creationell-captcha' ),
            'sub'      => __( 'Formulare + Interceptor', 'creationell-captcha' ),
            'modifier' => 'creationell-captcha-kpi-pass',
        ],
        [
            'value'    => number_format_i18n( (int) $h24['firewall'] + (int) $h24['ratelimit'] ),
            'label'    => __( 'Abgewehrt (24 h)', 'creationell-captcha' ),
            'sub'      => __( 'Firewall + Rate-Limit', 'creationell-captcha' ),
            'modifier' => 'creationell-captcha-kpi-blocked',
        ],
        [
            'value'    => number_format_i18n( (int) $h24['underattack'] ) . ' / ' . number_format_i18n( (int) $h24['underattack_passed'] ),
            'label'    => __( 'Under-Attack (24 h)', 'creationell-captcha' ),
            'sub'      => __( 'Abfragen / bestanden', 'creationell-captcha' ),
            'modifier' => 'creationell-captcha-kpi-underattack',
        ],
        [
            'value'    => number_format_i18n( (int) $h24['failed'] ),
            'label'    => __( 'Captcha fehlgeschlagen (24 h)', 'creationell-captcha' ),
            'sub'      => '',
            'modifier' => 'creationell-captcha-kpi-failed',
        ],
    ];
    ?>
    <div class="creationell-captcha-kpis">
        <?php foreach ( $kpis as $kpi ) : ?>
            <div class="creationell-captcha-kpi <?php echo esc_attr( $kpi['modifier'] ); ?>">
                <span class="creationell-captcha-kpi-value"><?php echo esc_html( $kpi['value'] ); ?></span>
                <span class="creationell-captcha-kpi-label"><?php echo esc_html( $kpi['label'] ); ?></span>
                <?php if ( '' !== $kpi['sub'] ) : ?>
                    <span class="creationell-captcha-kpi-sub"><?php echo esc_html( $kpi['sub'] ); ?></span>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>

    <?php foreach ( $groups as $group ) : ?>
        <div class="creationell-captcha-group-head">
            <h3><?php echo esc_html( $group['title'] ); ?></h3>
            <p><?php echo esc_html( $group['description'] ); ?></p>
        </div>
        <table class="widefat striped creationell-captcha-group-table">
            <thead>
                <tr>
                    <th><?php echo esc_html__( 'Ereignis', 'creationell-captcha' ); ?></th>
                    <?php foreach ( $windows as $window ) : ?>
                        <th><?php echo esc_html( $window['label'] ); ?></th>
                    <?php endforeach; ?>
                </tr>
            </thead>
            <tbody>
            <?php foreach ( $group['types'] as $type => $type_label ) : ?>
                <tr>
                    <td><?php echo esc_html( $type_label ); ?></td>
                    <?php foreach ( $windows as $window ) : ?>
                        <td><?php echo esc_html( number_format_i18n( (int) ( $window['totals'][ $type ] ?? 0 ) ) ); ?></td>
                    <?php endforeach; ?>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endforeach; ?>
    <?php
}

/**
 * Renders the "Verlauf" tab: the day-by-day table for the last 30 days.
 */
function creationell_captcha_render_analytics_history(): void {
    $analytics = creationell_captcha_analytics();
    $labels    = creationell_captcha_analytics_labels();
    $counts    = $analytics->get_daily_counts();
    ?>
    <h2><?php echo esc_html__( 'Verlauf (letzte 30 Tage)', 'creationell-captcha' ); ?></h2>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__( 'Tag', 'creationell-captcha' ); ?></th>
                <?php foreach ( $labels as $label ) : ?>
                    <th><?php echo esc_html( $label ); ?></th>
                <?php endforeach; ?>
            </tr>
        </thead>
        <tbody>
        <?php
        for ( $i = 0; $i < 30; $i++ ) {
            $day        = gmdate( 'Y-m-d', time() - $i * 86400 );
            $day_counts = isset( $counts[ $day ] ) && is_array( $counts[ $day ] ) ? $counts[ $day ] : [];
            ?>
            <tr>
                <td><?php echo esc_html( $day ); ?></td>
                <?php foreach ( array_keys( $labels ) as $type ) : ?>
                    <td><?php echo esc_html( (string) ( isset( $day_counts[ $type ] ) ? (int) $day_counts[ $type ] : 0 ) ); ?></td>
                <?php endforeach; ?>
            </tr>
            <?php
        }
        ?>
        </tbody>
    </table>
    <?php
}

/**
 * Reads and sanitises the event-log filter from the request.
 *
 * Used by the "Ereignisse" tab and by the CSV export handler. The values only
 * narrow a read-only query and are bound via $wpdb->prepare downstream, so no
 * nonce check is required here; the page number is read separately by the tab.
 *
 * @return array{search: string, event_type: string, date_from: string, date_to: string}
 */
function creationell_captcha_events_query_args(): array {
    $valid_date = static function ( string $value ): string {
        if ( 1 !== preg_match( '/^\d{4}-\d{2}-\d{2}$/', $value ) ) {
            return '';
        }
        $parts = array_map( 'intval', explode( '-', $value ) );

        return checkdate( $parts[1], $parts[2], $parts[0] ) ? $value : '';
    };

    // phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only filter, bound via $wpdb->prepare.
    $search     = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
    $event_type = isset( $_GET['event_type'] ) ? sanitize_key( wp_unslash( $_GET['event_type'] ) ) : '';
    $date_from  = isset( $_GET['date_from'] ) ? sanitize_text_field( wp_unslash( $_GET['date_from'] ) ) : '';
    $date_to    = isset( $_GET['date_to'] ) ? sanitize_text_field( wp_unslash( $_GET['date_to'] ) ) : '';
    // phpcs:enable WordPress.Security.NonceVerification.Recommended

    $types = array_keys( creationell_captcha_analytics_labels() );

    return [
        'search'     => $search,
        'event_type' => in_array( $event_type, $types, true ) ? $event_type : '',
        'date_from'  => $valid_date( $date_from ),
        'date_to'    => $valid_date( $date_to ),
    ];
}

/**
 * Renders the "Ereignisse" tab: filter toolbar, the event table with a detail
 * link per row, the embedded event data and the detail modal.
 */
function creationell_captcha_render_analytics_events(): void {
    $settings = creationell_captcha_get_settings();

    if ( empty( $settings['analytics_event_log'] ) ) {
        ?>
        <h2><?php echo esc_html__( 'Detaillierter Event-Log', 'creationell-captcha' ); ?></h2>
        <p><?php echo esc_html__( 'Der detaillierte Event-Log ist nicht aktiv. Er lässt sich unter „Einstellungen → CreaCaptcha" im Abschnitt „Analytics" einschalten.', 'creationell-captcha' ); ?></p>
        <?php
        return;
    }

    $analytics = creationell_captcha_analytics();
    $labels    = creationell_captcha_analytics_labels();

    if ( 0 === $analytics->count_events( [] ) ) {
        ?>
        <p><?php echo esc_html__( 'Noch keine Ereignisse aufgezeichnet.', 'creationell-captcha' ); ?></p>
        <?php
        return;
    }

    $filter = creationell_captcha_events_query_args();
    creationell_captcha_render_events_toolbar( $filter );

    $per_page = 50;
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only pagination index.
    $paged = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;

    $total       = $analytics->count_events( $filter );
    $total_pages = (int) max( 1, (int) ceil( $total / $per_page ) );
    $paged       = min( $paged, $total_pages );

    $rows = $analytics->query_events(
        $filter + [
            'limit'  => $per_page,
            'offset' => ( $paged - 1 ) * $per_page,
        ]
    );

    if ( empty( $rows ) ) {
        ?>
        <p><?php echo esc_html__( 'Keine Ereignisse für die aktuelle Filterung.', 'creationell-captcha' ); ?></p>
        <?php
        return;
    }

    // Build the id-keyed map for the detail modal, with display-ready values.
    $event_map = [];
    foreach ( $rows as $event ) {
        $id   = (string) ( $event['id'] ?? '' );
        $type = (string) ( $event['event_type'] ?? '' );

        $event['event_type']  = $labels[ $type ] ?? $type;
        $event['interceptor'] = empty( $event['interceptor'] )
            ? __( 'nein', 'creationell-captcha' )
            : __( 'ja', 'creationell-captcha' );
        $event['user_id'] = ( '0' === (string) ( $event['user_id'] ?? '0' ) )
            ? __( '0 (anonym)', 'creationell-captcha' )
            : (string) ( $event['user_id'] ?? '' );

        $event_map[ $id ] = $event;
    }

    $dash = static function ( $value ): string {
        $value = (string) $value;
        return '' === $value ? '—' : $value;
    };
    ?>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__( 'ID', 'creationell-captcha' ); ?></th>
                <th><?php echo esc_html__( 'Zeit (UTC)', 'creationell-captcha' ); ?></th>
                <th><?php echo esc_html__( 'Ereignis', 'creationell-captcha' ); ?></th>
                <th><?php echo esc_html__( 'Plugin', 'creationell-captcha' ); ?></th>
                <th><?php echo esc_html__( 'Aktion', 'creationell-captcha' ); ?></th>
                <th><?php echo esc_html__( 'Formular-ID', 'creationell-captcha' ); ?></th>
                <th><?php echo esc_html__( 'IP-Adresse', 'creationell-captcha' ); ?></th>
                <th><?php echo esc_html__( 'Details', 'creationell-captcha' ); ?></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ( $rows as $event ) : ?>
            <?php $event_type = (string) ( $event['event_type'] ?? '' ); ?>
            <tr>
                <td><?php echo esc_html( (string) ( $event['id'] ?? '' ) ); ?></td>
                <td><?php echo esc_html( (string) ( $event['created_at'] ?? '' ) ); ?></td>
                <td><?php echo esc_html( $labels[ $event_type ] ?? $event_type ); ?></td>
                <td><?php echo esc_html( $dash( $event['plugin'] ?? '' ) ); ?></td>
                <td><?php echo esc_html( $dash( $event['action'] ?? '' ) ); ?></td>
                <td><?php echo esc_html( $dash( $event['form_id'] ?? '' ) ); ?></td>
                <td><?php echo esc_html( (string) ( $event['ip'] ?? '' ) ); ?></td>
                <td>
                    <button type="button" class="button-link creationell-captcha-event-info" data-event-id="<?php echo esc_attr( (string) ( $event['id'] ?? '' ) ); ?>">
                        <?php echo esc_html__( 'ⓘ Info', 'creationell-captcha' ); ?>
                    </button>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php
    creationell_captcha_render_events_pagination( $filter, $paged, $total_pages );

    $json = wp_json_encode( $event_map, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );
    ?>
    <script type="application/json" id="creationell-captcha-events-data"><?php echo false === $json ? '{}' : $json; ?></script>
    <?php
    creationell_captcha_render_event_modal();
}

/**
 * Renders the (initially hidden) event-detail modal skeleton.
 *
 * The value cells carry a `data-field` matching the event record key; the modal
 * JavaScript fills them client-side from the embedded JSON map.
 */
function creationell_captcha_render_event_modal(): void {
    $fields = [
        'id'                => __( 'ID', 'creationell-captcha' ),
        'event_type'        => __( 'Ereignis', 'creationell-captcha' ),
        'created_at'        => __( 'Zeit (UTC)', 'creationell-captcha' ),
        'plugin'            => __( 'Plugin', 'creationell-captcha' ),
        'action'            => __( 'Aktion', 'creationell-captcha' ),
        'form_id'           => __( 'Formular-ID', 'creationell-captcha' ),
        'interceptor'       => __( 'Interceptor', 'creationell-captcha' ),
        'reason'            => __( 'Grund', 'creationell-captcha' ),
        'ip'                => __( 'IP-Adresse', 'creationell-captcha' ),
        'user_id'           => __( 'Benutzer-ID', 'creationell-captcha' ),
        'path'              => __( 'URL / Pfad', 'creationell-captcha' ),
        'referrer'          => __( 'Referrer', 'creationell-captcha' ),
        'user_agent'        => __( 'User-Agent', 'creationell-captcha' ),
        'verification_data' => __( 'Verifizierungsdaten', 'creationell-captcha' ),
        'request_body'      => __( 'Request-Body', 'creationell-captcha' ),
    ];
    ?>
    <div class="creationell-captcha-modal" id="creationell-captcha-event-modal" hidden>
        <div class="creationell-captcha-modal-backdrop" data-creationell-captcha-modal-close></div>
        <div class="creationell-captcha-modal-card" role="dialog" aria-modal="true" aria-labelledby="creationell-captcha-modal-title">
            <div class="creationell-captcha-modal-head">
                <strong id="creationell-captcha-modal-title"><?php echo esc_html__( 'Ereignis-Details', 'creationell-captcha' ); ?></strong>
                <button type="button" class="creationell-captcha-modal-x" data-creationell-captcha-modal-close aria-label="<?php echo esc_attr__( 'Schließen', 'creationell-captcha' ); ?>">&times;</button>
            </div>
            <div class="creationell-captcha-modal-body">
                <table class="widefat striped">
                    <tbody>
                    <?php foreach ( $fields as $key => $label ) : ?>
                        <tr>
                            <th scope="row"><?php echo esc_html( $label ); ?></th>
                            <td data-field="<?php echo esc_attr( $key ); ?>"></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php
}

/**
 * Renders the event-log filter toolbar: search, type filter, date range, the
 * "Filtern"/"Zurücksetzen" controls and the CSV export link.
 *
 * @param array{search: string, event_type: string, date_from: string, date_to: string} $filter Active filter.
 */
function creationell_captcha_render_events_toolbar( array $filter ): void {
    $labels   = creationell_captcha_analytics_labels();
    $base_url = menu_page_url( 'creationell-captcha-analytics', false );

    $has_filter = '' !== $filter['search'] || '' !== $filter['event_type']
        || '' !== $filter['date_from'] || '' !== $filter['date_to'];

    $export_url = wp_nonce_url(
        add_query_arg(
            [
                'action'     => 'creationell_captcha_export_events',
                's'          => $filter['search'],
                'event_type' => $filter['event_type'],
                'date_from'  => $filter['date_from'],
                'date_to'    => $filter['date_to'],
            ],
            admin_url( 'admin-post.php' )
        ),
        'creationell_captcha_export_events'
    );
    ?>
    <form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>" class="creationell-captcha-events-filter">
        <input type="hidden" name="page" value="creationell-captcha-analytics" />
        <input type="hidden" name="tab" value="events" />

        <input type="search" name="s" value="<?php echo esc_attr( $filter['search'] ); ?>" placeholder="<?php echo esc_attr__( 'IP-Adresse oder Pfad', 'creationell-captcha' ); ?>" />

        <select name="event_type" aria-label="<?php echo esc_attr__( 'Ereignistyp', 'creationell-captcha' ); ?>">
            <option value=""><?php echo esc_html__( 'Alle Ereignistypen', 'creationell-captcha' ); ?></option>
            <?php foreach ( $labels as $type => $label ) : ?>
                <option value="<?php echo esc_attr( $type ); ?>"<?php selected( $filter['event_type'], $type ); ?>><?php echo esc_html( $label ); ?></option>
            <?php endforeach; ?>
        </select>

        <input type="date" name="date_from" value="<?php echo esc_attr( $filter['date_from'] ); ?>" aria-label="<?php echo esc_attr__( 'Datum von', 'creationell-captcha' ); ?>" />
        <input type="date" name="date_to" value="<?php echo esc_attr( $filter['date_to'] ); ?>" aria-label="<?php echo esc_attr__( 'Datum bis', 'creationell-captcha' ); ?>" />

        <?php submit_button( __( 'Filtern', 'creationell-captcha' ), 'secondary', '', false ); ?>

        <?php if ( $has_filter ) : ?>
            <a href="<?php echo esc_url( add_query_arg( 'tab', 'events', $base_url ) ); ?>"><?php echo esc_html__( 'Zurücksetzen', 'creationell-captcha' ); ?></a>
        <?php endif; ?>

        <a href="<?php echo esc_url( $export_url ); ?>" class="button"><?php echo esc_html__( 'Als CSV exportieren', 'creationell-captcha' ); ?></a>
    </form>
    <?php
}

/**
 * Renders the pagination navigation below the event-log table.
 *
 * @param array{search: string, event_type: string, date_from: string, date_to: string} $filter      Active filter.
 * @param int                                                                            $paged       Current page (1-based).
 * @param int                                                                            $total_pages Total page count.
 */
function creationell_captcha_render_events_pagination( array $filter, int $paged, int $total_pages ): void {
    if ( $total_pages < 2 ) {
        return;
    }

    $links = paginate_links(
        [
            'base'      => admin_url( 'admin.php' ) . '?paged=%#%',
            'format'    => '',
            'current'   => $paged,
            'total'     => $total_pages,
            'add_args'  => [
                'page'       => 'creationell-captcha-analytics',
                'tab'        => 'events',
                's'          => $filter['search'],
                'event_type' => $filter['event_type'],
                'date_from'  => $filter['date_from'],
                'date_to'    => $filter['date_to'],
            ],
            'prev_text' => __( '‹ Zurück', 'creationell-captcha' ),
            'next_text' => __( 'Weiter ›', 'creationell-captcha' ),
        ]
    );

    if ( is_string( $links ) && '' !== $links ) {
        echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post( $links ) . '</div></div>';
    }
}
