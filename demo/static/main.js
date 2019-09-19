/* globals feather:false */

function uri2path(uri) {
    return (new URL(uri)).pathname
}

function sidebarHighlightCurrentLink() {
     $('#sidebar li.nav-item a.nav-link').each(function(){
        if (uri2path(window.location.href) == uri2path(this.href)) {
            $(this).addClass('active');
        }        
    });
}

function abbreviateHexStrings() {
    $(".abbrev-hex").html(function () {
        var text = $(this).text();
        text = text.replace(/0x([0-9a-fA-F]{4})([0-9a-fA-F]+)/mg,
            "<span class=\"expand-hex\" data-switchto=\"0x$1$2\">0x$1…</span>");
        return text;
    });

    $(".expand-hex").click(function(){
        var t2 = $(this).data("switchto");
        var t1 = $(this).text();
        $(this).data("switchto", t1);
        $(this).text(t2);
    });
}

(function () {
    'use strict'

    feather.replace();
    sidebarHighlightCurrentLink();
    abbreviateHexStrings();
}())
