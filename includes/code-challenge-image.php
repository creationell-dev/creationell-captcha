<?php
/**
 * PNG image renderer for the code-challenge. Uses PHP-GD with the vendored
 * DejaVuSans Bold TTF and a few naive anti-OCR distortions (per-character
 * rotation, two random lines, scattered noise pixels).
 *
 * @package Creationell\Captcha
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Renders a PNG of the given code and returns the raw bytes. Caller is
 * responsible for emitting headers (`Content-Type: image/png`,
 * `Cache-Control: no-store`) and the body.
 *
 * Falls back to GD's built-in bitmap font 5 if the vendored TTF is missing
 * (logs a one-line warning so the operator sees the degradation).
 *
 * @param string $code The code to render (4–8 chars expected; longer is
 *                     trimmed implicitly by the width budget).
 */
function creationell_captcha_render_code_image( string $code ): string {
    $width  = 180;
    $height = 60;
    $im     = imagecreatetruecolor( $width, $height );

    $white = imagecolorallocate( $im, 255, 255, 255 );
    $text  = imagecolorallocate( $im, 30, 30, 80 );
    $noise = imagecolorallocate( $im, 200, 200, 200 );

    imagefilledrectangle( $im, 0, 0, $width, $height, $white );

    // Two random lines across the canvas.
    for ( $i = 0; $i < 2; $i++ ) {
        imageline(
            $im,
            random_int( 0, $width ),
            random_int( 0, $height ),
            random_int( 0, $width ),
            random_int( 0, $height ),
            $noise
        );
    }

    // 80 scattered noise pixels.
    for ( $i = 0; $i < 80; $i++ ) {
        imagesetpixel(
            $im,
            random_int( 0, $width - 1 ),
            random_int( 0, $height - 1 ),
            $noise
        );
    }

    $font_path = CREATIONELL_CAPTCHA_PLUGIN_PATH . 'assets/fonts/captcha.ttf';
    $code_len  = strlen( $code );
    $char_w    = $width / max( 1, $code_len );

    if ( is_file( $font_path ) && function_exists( 'imagettftext' ) ) {
        // TTF path — pretty.
        for ( $i = 0; $i < $code_len; $i++ ) {
            $angle = random_int( -15, 15 );
            $x     = (int) ( $i * $char_w + 10 );
            $y     = random_int( $height - 15, $height - 10 );
            imagettftext( $im, 24, $angle, $x, $y, $text, $font_path, $code[ $i ] );
        }
    } else {
        // Bitmap fallback — ugly but functional.
        creationell_captcha_log( 'code-challenge: TTF font missing, falling back to bitmap font.' );
        $font_no = 5;
        for ( $i = 0; $i < $code_len; $i++ ) {
            $x = (int) ( $i * $char_w + 14 );
            $y = (int) ( $height / 2 - imagefontheight( $font_no ) / 2 );
            imagestring( $im, $font_no, $x, $y, $code[ $i ], $text );
        }
    }

    ob_start();
    imagepng( $im, null, 9 );
    imagedestroy( $im );
    return (string) ob_get_clean();
}
