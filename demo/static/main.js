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
        var text = $(this).html();
        var abbrev_length = parseInt($(this).data("abbrev-length") || "32");
        text = text.replace(/(0x)?([0-9a-fA-F]{16,})/mg, function(m, p1,p2, offset, whole) {
            p1 = p1 || "";
            if (p2.length <= abbrev_length*2) {
                return p1+p2;
            } 
            return "<span class=\"expand-hex\" data-switch-to=\"" + p1 + "" + p2 + "\">"+ 
                   p1 + "" + p2.substr(0,abbrev_length*2) + "…</span>";
        });
        return text;
    });

    $(".expand-hex").click(function(){
        var t2 = $(this).data("switch-to");
        var t1 = $(this).text();
        $(this).data("switch-to", t1);
        $(this).text(t2);
    });
}

function highlightZkvmOpcodes() {
    $(".highlight-zkvm").html(function(){
        var text = $(this).html();
        text = " " + text + " ";
        text = text.replace(/(\W)(push|drop|dup:\d+|roll:\d+|const|var|alloc|locktime|expr|neg|add|mul|eq|range|and|or|not|verify|unblind|issue|borrow|retire|cloak:\d+:\d+|input|output:\d+|contract:\d+|log|call|signtx|signid)/mg,
            "$1<span class=\"zkvm-op\">$2</span>");
        return text;
    })
}

function autofocusModals() {
    $('#new-node').on('shown.bs.modal', function() {
        $('#new-node-alias').focus();
    });
    $('#new-asset').on('shown.bs.modal', function() {
        $('#new-asset-alias').focus();
    });
}

function prepareTxShowDetails() {
    $(".tx-show-details").on("click", function(){
        $(".show-button-wrapper", this).hide();
        $(".details-being-shown", this).show();
    });
}

(function () {
    'use strict'

    feather.replace();
    sidebarHighlightCurrentLink();
    highlightZkvmOpcodes();
    abbreviateHexStrings();
    autofocusModals();
    prepareTxShowDetails();
}())
