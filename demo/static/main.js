/* globals feather:false */

function uri2path(uri) {
	return (new URL(uri)).pathname
}

function highlightCurrentLink() {
	 $('#sidebar li.nav-item a.nav-link').each(function(){
	 	if (uri2path(window.location.href) == uri2path(this.href)) {
 			$(this).addClass('active');
	 	}        
    });
}

(function () {
  'use strict'

  feather.replace();
  highlightCurrentLink();
}())
