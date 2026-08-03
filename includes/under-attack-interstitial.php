<?php
/**
 * Under-attack interstitial page.
 *
 * Rendered by Creationell\Captcha\UnderAttack::serve_interstitial(). Expects
 * these variables in scope:
 *   string                $action        Form action — the requested URL.
 *   string                $widget_src    URL of the bundled ALTCHA widget script.
 *   string                $challenge_url The challenge REST endpoint URL.
 *   string                $field         Hidden-field name for the solved challenge.
 *   string                $worker_inline Inline Argon2id worker-registration JS (or '').
 *   array<string, string> $texts         Four interstitial strings: title, heading, message, noscript.
 *   array<string, string> $colors        Two hex colour strings: background, text (each may be '').
 *   string                $user_css      Custom CSS appended after the default <style> block (or '').
 *   string                $logo_url      Optional logo image URL (or '').
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/** @var string $action */
/** @var string $widget_src */
/** @var string $challenge_url */
/** @var string $field */
/** @var string $worker_inline */
/** @var array<string, string> $texts */
/** @var array<string, string> $colors */
/** @var string $user_css */
/** @var string $logo_url */
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo esc_html( $texts['title'] ); ?></title>
    <style>
        :root {
            --creationell-captcha-ua-bg:   <?php echo esc_attr( '' !== $colors['background'] ? $colors['background'] : '#f0f0f1' ); ?>;
            --creationell-captcha-ua-text: <?php echo esc_attr( '' !== $colors['text']       ? $colors['text']       : '#1d2327' ); ?>;
        }
        body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: var(--creationell-captcha-ua-bg); color: var(--creationell-captcha-ua-text); margin: 0; display: flex; min-height: 100vh; align-items: center; justify-content: center; }
        .crea-ua { max-width: 420px; padding: 2.5rem 2rem; text-align: center; }
        .crea-ua h1 { font-size: 1.25rem; margin: 0 0 .75rem; }
        .crea-ua p { margin: 0 0 1rem; line-height: 1.5; }
        .crea-ua noscript { color: #b32d2e; }
        .crea-ua-logo { display: block; max-height: 128px; max-width: 100%; width: auto; margin: 0 auto 1.5rem; }
    </style>
    <?php if ( '' !== $user_css ) : ?>
    <?php // AF-2: Ausgabe-Härtung statt Vertrauen auf den Schreibpfad — mindestens drei Schreibwege erreichen den Sanitizer nie (W2). ?>
    <style><?php echo creationell_captcha_safe_inline_css( $user_css ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- creationell_captcha_safe_inline_css() entfernt jede Sequenz, die den <style>-Block beenden könnte. ?></style>
    <?php endif; ?>
    <script src="<?php echo esc_url( $widget_src ); ?>"></script>
    <?php if ( '' !== $worker_inline ) : ?>
    <script><?php echo $worker_inline; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from wp_json_encode of a plugin URL. ?></script>
    <?php endif; ?>
</head>
<body>
    <div class="crea-ua">
        <?php if ( '' !== $logo_url ) : ?>
        <img class="crea-ua-logo" src="<?php echo esc_url( $logo_url ); ?>" alt="<?php echo esc_attr( get_bloginfo( 'name' ) ); ?>">
        <?php endif; ?>
        <h1><?php echo esc_html( $texts['heading'] ); ?></h1>
        <p><?php echo esc_html( $texts['message'] ); ?></p>
        <form method="post" action="<?php echo esc_url( $action ); ?>" id="crea-ua-form">
            <altcha-widget
                challenge="<?php echo esc_url( $challenge_url ); ?>"
                name="<?php echo esc_attr( $field ); ?>"
                display="invisible"
                auto="onload"></altcha-widget>
            <noscript><?php echo esc_html( $texts['noscript'] ); ?></noscript>
        </form>
    </div>
    <script>
        ( function () {
            var form = document.getElementById( 'crea-ua-form' );
            var poll = setInterval( function () {
                var input = form.querySelector( 'input[name="<?php echo esc_js( $field ); ?>"]' );
                if ( input && input.value ) {
                    clearInterval( poll );
                    form.submit();
                }
            }, 200 );
        } )();
    </script>
</body>
</html>
