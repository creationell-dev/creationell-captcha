/**
 * CreaCaptcha — Admin-Tab-Umschaltung.
 *
 * Schaltet die Tab-Panels der tab-gegliederten Admin-Seiten per Klick um. Wo
 * ein Einstellungsformular vorhanden ist (Settings-Seite), wird der aktive Tab
 * zusätzlich in die Browser-URL und in das versteckte _wp_http_referer-Feld
 * geschrieben, damit nach dem Speichern (Seiten-Reload) derselbe Tab wieder
 * aktiv ist; Seiten ohne Formular (Statistik) überspringen diesen Teil.
 */
( function () {
	'use strict';

	var wrap = document.querySelector( '.creationell-captcha-tabbed' );

	if ( ! wrap ) {
		return;
	}

	var navLinks = wrap.querySelectorAll( '.creationell-captcha-tabs-nav .nav-tab' );
	var panels   = wrap.querySelectorAll( '.creationell-captcha-tab' );
	var referer  = wrap.querySelector( 'input[name="_wp_http_referer"]' );

	/**
	 * Writes the active tab id into the page URL and the hidden
	 * _wp_http_referer field, so the tab survives the post-save reload.
	 */
	function syncTab( tabId ) {
		if ( window.history && window.history.replaceState ) {
			var pageUrl = new URL( window.location.href );
			pageUrl.searchParams.set( 'tab', tabId );
			window.history.replaceState( null, '', pageUrl.toString() );
		}

		if ( referer ) {
			var refUrl = new URL( referer.value, window.location.origin );
			refUrl.searchParams.set( 'tab', tabId );
			referer.value = refUrl.pathname + refUrl.search;
		}
	}

	/**
	 * Activates the tab with the given id and hides the others.
	 */
	function activate( tabId ) {
		var i;

		for ( i = 0; i < navLinks.length; i++ ) {
			navLinks[ i ].classList.toggle(
				'nav-tab-active',
				navLinks[ i ].getAttribute( 'data-tab' ) === tabId
			);
		}

		for ( i = 0; i < panels.length; i++ ) {
			panels[ i ].classList.toggle(
				'is-active',
				panels[ i ].getAttribute( 'data-tab' ) === tabId
			);
		}

		syncTab( tabId );
	}

	for ( var n = 0; n < navLinks.length; n++ ) {
		navLinks[ n ].addEventListener( 'click', function ( event ) {
			event.preventDefault();
			activate( this.getAttribute( 'data-tab' ) );
		} );
	}
} )();

/**
 * CreaCaptcha — Bestätigungsdialog für destruktive Werkzeuge-Buttons.
 *
 * Hängt an jeden Button mit der Klasse .creationell-captcha-confirm einen
 * confirm()-Dialog; bricht der Nutzer ab, wird das Absenden verhindert.
 */
( function () {
	'use strict';

	var buttons = document.querySelectorAll( '.creationell-captcha-confirm' );

	for ( var i = 0; i < buttons.length; i++ ) {
		buttons[ i ].addEventListener( 'click', function ( event ) {
			var message = this.getAttribute( 'data-confirm' )
				|| 'Diese Aktion kann nicht rückgängig gemacht werden. Fortfahren?';
			if ( ! window.confirm( message ) ) {
				event.preventDefault();
			}
		} );
	}
} )();

/**
 * CreaCaptcha — Detail-Fenster für Event-Log-Einträge.
 *
 * Liest die in die Seite eingebettete JSON-Map der Ereignisse und füllt das
 * Modal bei Klick auf einen „Info"-Button rein clientseitig. Werte werden
 * ausschließlich per textContent gesetzt — kein HTML, kein XSS-Risiko.
 */
( function () {
	'use strict';

	var modal = document.getElementById( 'creationell-captcha-event-modal' );
	var data  = document.getElementById( 'creationell-captcha-events-data' );

	if ( ! modal || ! data ) {
		return;
	}

	var events = {};
	try {
		events = JSON.parse( data.textContent || '{}' );
	} catch ( e ) {
		return;
	}

	function openModal( id ) {
		var event = events[ id ];
		if ( ! event ) {
			return;
		}

		var title = document.getElementById( 'creationell-captcha-modal-title' );
		if ( title ) {
			title.textContent = 'Ereignis-Details — #' + id;
		}

		var cells = modal.querySelectorAll( '[data-field]' );
		for ( var i = 0; i < cells.length; i++ ) {
			var value = event[ cells[ i ].getAttribute( 'data-field' ) ];
			cells[ i ].textContent = ( null === value || undefined === value || '' === value )
				? '—'
				: String( value );
		}

		modal.hidden = false;
	}

	function closeModal() {
		modal.hidden = true;
	}

	var buttons = document.querySelectorAll( '.creationell-captcha-event-info' );
	for ( var b = 0; b < buttons.length; b++ ) {
		buttons[ b ].addEventListener( 'click', function () {
			openModal( this.getAttribute( 'data-event-id' ) );
		} );
	}

	var closers = modal.querySelectorAll( '[data-creationell-captcha-modal-close]' );
	for ( var c = 0; c < closers.length; c++ ) {
		closers[ c ].addEventListener( 'click', closeModal );
	}

	document.addEventListener( 'keydown', function ( event ) {
		if ( 'Escape' === event.key && ! modal.hidden ) {
			closeModal();
		}
	} );
} )();
