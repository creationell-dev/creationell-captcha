/**
 * CreaCaptcha — email-obfuscation decoder.
 *
 * Restores addresses encoded by Creationell\Captcha\EmailObfuscator: the first
 * hex byte is the XOR key, every following byte is decoded back with it.
 */
( function () {
	'use strict';

	function decode( hex ) {
		if ( ! hex || hex.length < 4 || hex.length % 2 !== 0 ) {
			return '';
		}
		var key = parseInt( hex.substr( 0, 2 ), 16 );
		var out = '';
		for ( var i = 2; i < hex.length; i += 2 ) {
			out += String.fromCharCode( parseInt( hex.substr( i, 2 ), 16 ) ^ key );
		}
		return out;
	}

	function reveal( el ) {
		var value = decode( el.getAttribute( 'data-cce' ) );
		if ( ! value ) {
			return;
		}

		// Was a mailto: link — restore the href, keep label and attributes.
		if ( 'A' === el.tagName ) {
			el.setAttribute( 'href', 'mailto:' + value );
			el.removeAttribute( 'data-cce' );
			return;
		}

		// A <span> inside an existing link — show the address as plain text,
		// no nested anchor.
		var parentLink = el.closest ? el.closest( 'a' ) : null;
		if ( parentLink ) {
			el.textContent = value;
			el.removeAttribute( 'data-cce' );
			return;
		}

		// A standalone <span> — replace it with a real mailto link.
		if ( el.parentNode ) {
			var link = document.createElement( 'a' );
			link.setAttribute( 'href', 'mailto:' + value );
			link.textContent = value;
			el.parentNode.replaceChild( link, el );
		}
	}

	function run() {
		var nodes = document.querySelectorAll( '[data-cce]' );
		for ( var i = 0; i < nodes.length; i++ ) {
			reveal( nodes[ i ] );
		}
	}

	if ( 'loading' !== document.readyState ) {
		run();
	} else {
		document.addEventListener( 'DOMContentLoaded', run );
	}
} )();
