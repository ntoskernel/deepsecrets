# -*- coding: utf-8 -*-

import unittest

from dexter.models import Document, db
from dexter.models.seeds import seed_db
from dexter.processing.crawlers import CitizenCrawler


class TestTimesliveCrawler(unittest.TestCase):
    def setUp(self):
        self.crawler = CitizenCrawler()

        self.db = db
        self.db.drop_all()
        self.db.create_all()
        seed_db(db)

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()

    def test_canonicalise_url(self):
        self.assertEqual(
            self.crawler.canonicalise_url('https://www.citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement'),
            'http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/',
        )

    def test_offer(self):
        self.assertEqual(
            self.crawler.offer('http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/'), True
        )
        # ignore non-citizen
        self.assertEqual(
            self.crawler.offer(
                'http://www.iol.co.za/news/crime-courts/justice-system-not-equipped-for-cable-theft-1.1760799'
            ),
            False,
        )

    def test_extract(self):
        html = """

<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge"><script type="text/javascript">window.NREUM||(NREUM={}),__nr_require=function(t,e,n){function r(n){if(!e[n]){var o=e[n]={exports:{}};t[n][0].call(o.exports,function(e){var o=t[n][1][e];return r(o||e)},o,o.exports)}return e[n].exports}if("function"==typeof __nr_require)return __nr_require;for(var o=0;o<n.length;o++)r(n[o]);return r}({QJf3ax:[function(t,e){function n(){}function r(t){function e(t){return t&&t instanceof n?t:t?a(t,i,o):o()}function c(n,r,o){t&&t(n,r,o);for(var i=e(o),a=f(n),c=a.length,u=0;c>u;u++)a[u].apply(i,r);return i}function u(t,e){p[t]=f(t).concat(e)}function f(t){return p[t]||[]}function s(){return r(c)}var p={};return{on:u,emit:c,create:s,listeners:f,context:e,_events:p}}function o(){return new n}var i="nr@context",a=t("gos");e.exports=r()},{gos:"7eSDFh"}],ee:[function(t,e){e.exports=t("QJf3ax")},{}],3:[function(t,e){function n(t){return function(){r(t,[(new Date).getTime()].concat(i(arguments)))}}var r=t("handle"),o=t(1),i=t(2);"undefined"==typeof window.newrelic&&(newrelic=window.NREUM);var a=["setPageViewName","addPageAction","setCustomAttribute","finished","addToTrace","inlineHit","noticeError"];o(a,function(t,e){window.NREUM[e]=n("api-"+e)}),e.exports=window.NREUM},{1:12,2:13,handle:"D5DuLP"}],gos:[function(t,e){e.exports=t("7eSDFh")},{}],"7eSDFh":[function(t,e){function n(t,e,n){if(r.call(t,e))return t[e];var o=n();if(Object.defineProperty&&Object.keys)try{return Object.defineProperty(t,e,{value:o,writable:!0,enumerable:!1}),o}catch(i){}return t[e]=o,o}var r=Object.prototype.hasOwnProperty;e.exports=n},{}],D5DuLP:[function(t,e){function n(t,e,n){return r.listeners(t).length?r.emit(t,e,n):void(r.q&&(r.q[t]||(r.q[t]=[]),r.q[t].push(e)))}var r=t("ee").create();e.exports=n,n.ee=r,r.q={}},{ee:"QJf3ax"}],handle:[function(t,e){e.exports=t("D5DuLP")},{}],XL7HBI:[function(t,e){function n(t){var e=typeof t;return!t||"object"!==e&&"function"!==e?-1:t===window?0:i(t,o,function(){return r++})}var r=1,o="nr@id",i=t("gos");e.exports=n},{gos:"7eSDFh"}],id:[function(t,e){e.exports=t("XL7HBI")},{}],G9z0Bl:[function(t,e){function n(){if(!v++){var t=l.info=NREUM.info,e=f.getElementsByTagName("script")[0];if(t&&t.licenseKey&&t.applicationID&&e){c(p,function(e,n){t[e]||(t[e]=n)});var n="https"===s.split(":")[0]||t.sslForHttp;l.proto=n?"https://":"http://",a("mark",["onload",i()]);var r=f.createElement("script");r.src=l.proto+t.agent,e.parentNode.insertBefore(r,e)}}}function r(){"complete"===f.readyState&&o()}function o(){a("mark",["domContent",i()])}function i(){return(new Date).getTime()}var a=t("handle"),c=t(1),u=window,f=u.document;t(2);var s=(""+location).split("?")[0],p={beacon:"bam.nr-data.net",errorBeacon:"bam.nr-data.net",agent:"js-agent.newrelic.com/nr-852.min.js"},d=window.XMLHttpRequest&&XMLHttpRequest.prototype&&XMLHttpRequest.prototype.addEventListener&&!/CriOS/.test(navigator.userAgent),l=e.exports={offset:i(),origin:s,features:{},xhrWrappable:d};f.addEventListener?(f.addEventListener("DOMContentLoaded",o,!1),u.addEventListener("load",n,!1)):(f.attachEvent("onreadystatechange",r),u.attachEvent("onload",n)),a("mark",["firstbyte",i()]);var v=0},{1:12,2:3,handle:"D5DuLP"}],loader:[function(t,e){e.exports=t("G9z0Bl")},{}],12:[function(t,e){function n(t,e){var n=[],o="",i=0;for(o in t)r.call(t,o)&&(n[i]=e(o,t[o]),i+=1);return n}var r=Object.prototype.hasOwnProperty;e.exports=n},{}],13:[function(t,e){function n(t,e,n){e||(e=0),"undefined"==typeof n&&(n=t?t.length:0);for(var r=-1,o=n-e||0,i=Array(0>o?0:o);++r<o;)i[r]=t[e+r];return i}e.exports=n},{}]},{},["G9z0Bl"]);</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="google-site-verification" content="J-VKfjAloHtBN8M39xLBBFs84NSIkkSOfd9cqUZQmk0"/>
<link rel="icon" type="image/png" href="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/favicon.png?b644a6">

            <title>
Outa claims proof of e-toll mismanagement | The Citizen         </title>
<meta name="msapplication-TileColor" content="#DE070F">
<meta name="msapplication-TileImage" content="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/tileicon.png">

        <!--sharing for single page-->
        	<meta property="og:image" content="http://citizen.co.za/wp-content/uploads/sites/18/2014/01/et13-602x400.jpg " />
        	<meta property="og:title" content="Outa claims proof of e-toll mismanagement"/>
        	<meta property="og:description" content="The Opposition to Urban Tolling Alliance (Outa) has once again pleaded with government to listen to “critics” against e-tolling, in light of new information provided by a whistle blower on the user payment system.
" />
        	<meta property="og:url" content="http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/"/>
        	<meta property="og:site_name" content="The Citizen"/>
        	<meta property="og:type" content="article"/>
        	<meta name="twitter:card" content="summary" />
        	<meta name="twitter:site" content="@TheCitizen_News" />
        	<meta name="twitter:title" content="Outa claims proof of e-toll mismanagement" />
        	<meta name="twitter:description" content="The Opposition to Urban Tolling Alliance (Outa) has once again pleaded with government to listen to “critics” against e-tolling, in light of new information provided by a whistle blower on the user payment system.
" />
        	<meta name="twitter:image" content="http://citizen.co.za/wp-content/uploads/sites/18/2014/01/et13-602x400.jpg" />
        	<meta name="twitter:url" content="http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/" />

<!--Author and publication meta tags-->
            	<meta name="author" content="Yadhana Jadoo &amp; Alex Mitchley "/>
    <!--sharing multimedia citizen-->
    <!--sharing fanzone/phakaaathi multimedia-->
    <!--end fanzone sharing-->

	<link rel="apple-touch-icon" href="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/touchicon.png?b644a6">


<!-- This site is optimized with the Yoast SEO plugin v3.0.7 - https://yoast.com/wordpress/plugins/seo/ -->
<meta name="description" content="The Opposition to Urban Tolling Alliance (Outa) has once again pleaded with government to listen to “critics” against e-tolling, in light of new information provided by a whistle blower on the user payment system."/>
<meta name="news_keywords" content="howard dembovsky, jpsa, justice project south africa, opposition to urban tolling alliance, outa, wayne duvenage, citizen, the citizen, news" />
<link rel="original-source" href="http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/" />
<meta name="robots" content="noodp,noydir"/>
<link rel="canonical" href="http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/" />
<!-- / Yoast SEO plugin. -->

<link rel="alternate" type="application/rss+xml" title="The Citizen &raquo; Feed" href="http://citizen.co.za/feed/" />
<link rel="alternate" type="application/rss+xml" title="The Citizen &raquo; Comments Feed" href="http://citizen.co.za/comments/feed/" />
<link rel="alternate" type="application/rss+xml" title="The Citizen &raquo; Outa claims proof of e-toll mismanagement Comments Feed" href="http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/feed/" />
		<script type="text/javascript">
			window._wpemojiSettings = {"baseUrl":"http:\/\/s.w.org\/images\/core\/emoji\/72x72\/","ext":".png","source":{"wpemoji":"http:\/\/citizen.co.za\/wp-includes\/js\/wp-emoji.js?ver=4.3.1","twemoji":"http:\/\/citizen.co.za\/wp-includes\/js\/twemoji.js?ver=4.3.1"}};
			( function( window, document, settings ) {
	var src, ready;

	/**
	 * Detect if the browser supports rendering emoji or flag emoji. Flag emoji are a single glyph
	 * made of two characters, so some browsers (notably, Firefox OS X) don't support them.
	 *
	 * @since 4.2.0
	 *
	 * @param type {String} Whether to test for support of "simple" or "flag" emoji.
	 * @return {Boolean} True if the browser can render emoji, false if it cannot.
	 */
	function browserSupportsEmoji( type ) {
		var canvas = document.createElement( 'canvas' ),
			context = canvas.getContext && canvas.getContext( '2d' );

		if ( ! context || ! context.fillText ) {
			return false;
		}

		/*
		 * Chrome on OS X added native emoji rendering in M41. Unfortunately,
		 * it doesn't work when the font is bolder than 500 weight. So, we
		 * check for bold rendering support to avoid invisible emoji in Chrome.
		 */
		context.textBaseline = 'top';
		context.font = '600 32px Arial';

		if ( type === 'flag' ) {
			/*
			 * This works because the image will be one of three things:
			 * - Two empty squares, if the browser doesn't render emoji
			 * - Two squares with 'G' and 'B' in them, if the browser doesn't render flag emoji
			 * - The British flag
			 *
			 * The first two will encode to small images (1-2KB data URLs), the third will encode
			 * to a larger image (4-5KB data URL).
			 */
			context.fillText( String.fromCharCode( 55356, 56812, 55356, 56807 ), 0, 0 );
			return canvas.toDataURL().length > 3000;
		} else {
			/*
			 * This creates a smiling emoji, and checks to see if there is any image data in the
			 * center pixel. In browsers that don't support emoji, the character will be rendered
			 * as an empty square, so the center pixel will be blank.
			 */
			context.fillText( String.fromCharCode( 55357, 56835 ), 0, 0 );
			return context.getImageData( 16, 16, 1, 1 ).data[0] !== 0;
		}
	}

	function addScript( src ) {
		var script = document.createElement( 'script' );

		script.src = src;
		script.type = 'text/javascript';
		document.getElementsByTagName( 'head' )[0].appendChild( script );
	}

	settings.supports = {
		simple: browserSupportsEmoji( 'simple' ),
		flag:   browserSupportsEmoji( 'flag' )
	};

	settings.DOMReady = false;
	settings.readyCallback = function() {
		settings.DOMReady = true;
	};

	if ( ! settings.supports.simple || ! settings.supports.flag ) {
		ready = function() {
			settings.readyCallback();
		};

		if ( document.addEventListener ) {
			document.addEventListener( 'DOMContentLoaded', ready, false );
			window.addEventListener( 'load', ready, false );
		} else {
			window.attachEvent( 'onload', ready );
			document.attachEvent( 'onreadystatechange', function() {
				if ( 'complete' === document.readyState ) {
					settings.readyCallback();
				}
			} );
		}

		src = settings.source || {};

		if ( src.concatemoji ) {
			addScript( src.concatemoji );
		} else if ( src.wpemoji && src.twemoji ) {
			addScript( src.twemoji );
			addScript( src.wpemoji );
		}
	}

} )( window, document, window._wpemojiSettings );
		</script>
		<style type="text/css">
img.wp-smiley,
img.emoji {
	display: inline !important;
	border: none !important;
	box-shadow: none !important;
	height: 1em !important;
	width: 1em !important;
	margin: 0 .07em !important;
	vertical-align: -0.1em !important;
	background: none !important;
	padding: 0 !important;
}
</style>
<link rel='stylesheet' id='slideshow-style-css'  href="http://citizen.co.za/wp-content/plugins/caxton-citizen-flexslider-wp-gallery/flexslider.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='fontawesome-css'  href="http://citizen.co.za/wp-content/themes/citizen-v5-2/css/font-awesome.min.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='bootstrap-css'  href="http://citizen.co.za/wp-content/themes/citizen-v5-2/css/bootstrap.min.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='citizen-css'  href="http://citizen.co.za/wp-content/themes/citizen-v5-2/style.min.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='ubermenu-css'  href="http://citizen.co.za/wp-content/plugins/ubermenu/pro/assets/css/ubermenu.min.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='ubermenu-font-awesome-css'  href="http://citizen.co.za/wp-content/plugins/ubermenu/assets/css/fontawesome/css/font-awesome.min.css?b644a6" type='text/css' media='all' />
<script type='text/javascript' src="http://citizen.co.za/wp-includes/js/jquery/jquery.js?b644a6"></script>
<script type='text/javascript' src="http://citizen.co.za/wp-includes/js/jquery/jquery-migrate.js?b644a6"></script>

<link rel='shortlink' href='http://citizen.co.za/?p=153078' />
<script src='http://sites.citizen.co.za/?dm=30ac966bcb8abbcd6995bb5168a584e5&amp;action=load&amp;blogid=18&amp;siteid=1&amp;t=1629846049&amp;back=http%3A%2F%2Fcitizen.co.za%2F153078%2Fouta-claims-proof-e-toll-mismanagement%2F' type='text/javascript'></script><style id="ubermenu-custom-generated-css">
/** UberMenu Custom Menu Styles (Customizer) **/
/* main */
.ubermenu-main .ubermenu-row { max-width:900px; margin-left:auto; margin-right:auto; }
.ubermenu-main.ubermenu-transition-slide .ubermenu-active > .ubermenu-submenu.ubermenu-submenu-type-mega,.ubermenu-main:not(.ubermenu-transition-slide) .ubermenu-submenu.ubermenu-submenu-type-mega,.ubermenu .ubermenu-force > .ubermenu-submenu { max-height:900px; }
.ubermenu-main.ubermenu-transition-fade .ubermenu-item .ubermenu-submenu-drop { margin-top:0; }
.ubermenu-main .ubermenu-nav .ubermenu-item.ubermenu-item-level-0 > .ubermenu-target { font-weight:normal; }


/* Status: Loaded from Transient */

</style>
<!--Google Analytics code starts-->
<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

ga('create', 'UA-1099200-1', 'auto');
ga('create', 'UA-1099200-10', 'auto', {'name': 'titleSiteRollup'});
ga('create', 'UA-27087662-4', 'auto', {'name': 'caxtonWMSRollup'});
ga('create', 'UA-1099200-21', 'auto', {'name': 'citizenIndividual'});
ga('require', 'displayfeatures');
ga('send', 'pageview', {'dimension1': 'news'});
ga('titleSiteRollup.send', 'pageview');
ga('caxtonWMSRollup.send', 'pageview');
ga('citizenIndividual.require', 'displayfeatures');
ga('citizenIndividual.send', 'pageview');
</script>
<!--Google Analytics code ends-->

<!-- Google search starts -->
<script>
    (function() {
        var cx = '016524336882760202931:h14uom3uglu';
        var gcse = document.createElement('script');
        gcse.type = 'text/javascript';
        gcse.async = true;
        gcse.src = (document.location.protocol == 'https:' ? 'https:' : 'http:') +
            '//cse.google.com/cse.js?cx=' + cx;
        var s = document.getElementsByTagName('script')[0];
        s.parentNode.insertBefore(gcse, s);
    })();
</script>
<!-- Google search ends -->


</head>
<body>
<!-- Facebook page API code starts/ also pull the facebook connect code then cache it-->
<script>
jQuery.ajax({
type: "GET",
url: "//connect.facebook.net/en_US/sdk.js",
success: function(){},
dataType: "script",
cache: true
});
</script>

<div id="fb-root"></div>
<script>
(function(d, s, id) {
  var js, fjs = d.getElementsByTagName(s)[0];
  if (d.getElementById(id)) return;
  js = d.createElement(s); js.id = id;
  js.src = "//connect.facebook.net/en_US/sdk.js#xfbml=1&version=v2.4&appId=1620518884863337";
  fjs.parentNode.insertBefore(js, fjs);
}(document, 'script', 'facebook-jssdk'));
</script>
<!-- Facebook page API code ends -->

<div class="wrapper">

               <div class="container hidden-sm hidden-xs" style="text-align: center;">
               <div class="leaderboard">
                   <!--/* OpenX JavaScript tag */-->

<!-- /*
 * The tag in this template has been generated for use on a
 * non-SSL page. If this tag is to be placed on an SSL page, change the
 * 'http://ox-d.caxton.co.za/...'
 * to
 * 'https://ox-d.caxton.co.za/...'
 */ -->

<script type="text/javascript">
  if (!window.OX_ads) { OX_ads = []; }
  OX_ads.push({ "auid" : "459167" });
</script>

<script type="text/javascript">
  document.write('<scr'+'ipt  src="http://ox-d.caxton.co.za/w/1.0/jstag"><\/scr'+'ipt>');
</script>

<noscript><iframe id="2c0ab9c086" name="2c0ab9c086" src="http://ox-d.caxton.co.za/w/1.0/afr?auid=459167&cb=INSERT_RANDOM_NUMBER_HERE" frameborder="0" scrolling="no" width="970" height="90"><a href="http://ox-d.caxton.co.za/w/1.0/rc?cs=2c0ab9c086&cb=INSERT_RANDOM_NUMBER_HERE" ><img src="http://ox-d.caxton.co.za/w/1.0/ai?auid=459167&cs=2c0ab9c086&cb=INSERT_RANDOM_NUMBER_HERE" border="0" alt=""></a></iframe></noscript>               </div><!--end leaderboard-->
           </div><!--end container theleaderboard-->
        
    <div class="header">
        <!-- Fixed header starts (This header is fixed but only appears when you 200px down a page, jQuery(window).scroll) -->
        <div class="fixed-menu-header">
            <div class="container">
                <div class="row">
                    <div class="col-md-3">
                                                    <a href="http://citizen.co.za" id="home" title="The Citizen - More News. Your Way"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/logo.png?b644a6" class="logo img-responsive" alt="The Citizen - More News. Your Way" title="The Citizen - More News. Your Way" /></a>
                                                </div>
                    <div class="col-md-9 menu-container navigation">
                        <ul class="header-icon-container pull-right nav">
                            <a href="#" class="header-icon search_button_static">
                                <span class="fa fa-search"></span>&nbsp;Search
                            </a>
                            <!-- <a href="#" class="header-icon"><span class="fa fa-sign-in"></span>&nbsp;Sign in</a> -->
                            <a href="http://citizen.co.za/subscribe/" class="header-icon"><span class="fa fa-envelope"></span>&nbsp;Subscribe</a>
                            <div class="search_website_static">
                                <gcse:searchbox-only resultsUrl="http://citizen.co.za/citizen-google-search/"></gcse:searchbox-only>
                            </div>
                        </ul><!--end header-icon-container pull-right nav-->
                        <!-- <ul class="social-icons pull-right">
                           <li><a href="https://www.facebook.com/TheCitizenNewsSA" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/facebook-icon-citizen.png?b644a6" alt="Facebook - Citizen" title="Facebook - Citizen" /></a></li>
                           <li><a href="https://plus.google.com/113672304772993300897" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/google-plus-citizen.png?b644a6" alt="Google Plus - Citizen" title="Google Plus - Citizen" /></a></li>
                           <li><a href="https://www.linkedin.com/company/54745" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/linkedin-icon-citizen.png?b644a6" alt="Linkedin - Citizen" title="Linkedin - Citizen" /></a></li>
                           <li><a href="http://twitter.com/intent/follow?source=followbutton&variant=1.0&screen_name=TheCitizen_News" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/twitter-icon-citizen.png?b644a6" alt="Twitter - Citizen" title="Twitter - Citizen" /></a></li>
                           <li><a href="https://www.youtube.com/channel/UCQ0qSGC8vs7l8kNHLRxkZpw" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/youtube-icon-citizen.png?b644a6" alt="Youtube - Citizen" title="Youtube - Citizen" /></a></li>
                        </ul> -->
                    </div>
                </div>
            </div>
        </div>
        <!-- Fixed header ends -->

        <!-- Main header starts (this header moves when you scroll up and down the page) -->
        <div class="main-menu-header">
            <div class="container">
                <div class="row">
                    <div class="col-md-3">
                                                    <a href="http://citizen.co.za" id="home" title="The Citizen - More News. Your Way"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/logo.png?b644a6" class="logo img-responsive" alt="The Citizen - More News. Your Way" title="The Citizen - More News. Your Way" /></a>
                                                </div>
                    <div class="col-md-9 menu-container navigation">    
                        <ul class="header-icon-container pull-right nav">
                            <a href="#" class="header-icon search_button_variable">
                                <span class="fa fa-search"></span>&nbsp;Search
                            </a>
                            <!-- <a href="#" class="header-icon"><span class="fa fa-sign-in"></span>&nbsp;Sign in</a> -->
                            <a href="http://citizen.co.za/subscribe/" class="header-icon"><span class="fa fa-envelope"></span>&nbsp;Subscribe</a>
                            <div class="search_website_variable">
                                <gcse:searchbox-only resultsUrl="http://citizen.co.za/citizen-google-search/"></gcse:searchbox-only>
                            </div>
                        </ul>
                        <ul class="social-icons pull-right">
                           <li><a href="https://www.facebook.com/TheCitizenNewsSA" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/facebook-icon-citizen.png?b644a6" alt="Facebook - Citizen" title="Facebook - Citizen" /></a></li>
                           <li><a href="https://plus.google.com/113672304772993300897" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/google-plus-citizen.png?b644a6" alt="Google Plus - Citizen" title="Google Plus - Citizen" /></a></li>
                           <li><a href="https://www.linkedin.com/company/54745" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/linkedin-icon-citizen.png?b644a6" alt="Linkedin - Citizen" title="Linkedin - Citizen" /></a></li>
                           <li><a href="http://twitter.com/intent/follow?source=followbutton&variant=1.0&screen_name=TheCitizen_News" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/twitter-icon-citizen.png?b644a6" alt="Twitter - Citizen" title="Twitter - Citizen" /></a></li>
                           <li><a href="https://www.youtube.com/channel/UCQ0qSGC8vs7l8kNHLRxkZpw" target="_blank"><img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/social-icons/youtube-icon-citizen.png?b644a6" alt="Youtube - Citizen" title="Youtube - Citizen" /></a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        <!-- Main header ends -->

        <div class="navigation-container">
            <div class="container">
                <div class="row">
                    <div class="col-md-12 main_menu">
                        
<!-- UberMenu [Configuration:main] [Theme Loc:main-navigation] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-main-navigation ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-110-main-navigation"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-110-main-navigation" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-110 ubermenu-loc-main-navigation ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-110-main-navigation" class="ubermenu-nav"><li id="menu-item-22097" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-22097 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://www.citizen.co.za/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Home</span></a></li><li id="menu-item-3536" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-current-post-ancestor ubermenu-item-has-children ubermenu-item-3536 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">NEWS</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-3536 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-1789" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-current-post-ancestor ubermenu-current-menu-parent ubermenu-current-post-parent ubermenu-item-1789 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-national/"><span class="ubermenu-target-title ubermenu-target-text">National</span></a></li><li id="menu-item-863411" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-863411 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/drought/"><span class="ubermenu-target-title ubermenu-target-text">drought</span></a></li><li id="menu-item-1787" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-1787 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-africa/"><span class="ubermenu-target-title ubermenu-target-text">Africa</span></a></li><li id="menu-item-1790" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-1790 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-world/"><span class="ubermenu-target-title ubermenu-target-text">World</span></a></li><li id="menu-item-954050" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-954050 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/wef-davos-2016/"><span class="ubermenu-target-title ubermenu-target-text">WEF Davos 2016</span></a></li><li id="menu-item-295160" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-295160 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-national/news-load-shading/"><span class="ubermenu-target-title ubermenu-target-text">Load Shedding</span></a></li><li id="menu-item-889935" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-889935 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-eish/"><span class="ubermenu-target-title ubermenu-target-text">Eish!</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-795476" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-has-children ubermenu-item-795476 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/business/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">BUSINESS</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-795476 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-795522" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-795522 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/business/business-news/"><span class="ubermenu-target-title ubermenu-target-text">Business News</span></a></li><li id="menu-item-795524" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-795524 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/business/business-personal-finance/"><span class="ubermenu-target-title ubermenu-target-text">Personal Finance</span></a></li><li id="menu-item-795526" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-795526 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/business/business-small-business/"><span class="ubermenu-target-title ubermenu-target-text">My Small Business</span></a></li><li id="menu-item-795478" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-795478 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/business/business-analysis-and-profiles/"><span class="ubermenu-target-title ubermenu-target-text">Analysis &#038; Profiles</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-203541" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-has-children ubermenu-item-203541 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">SPORT</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-203541 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-217406" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-217406 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/"><span class="ubermenu-target-title ubermenu-target-text">Soccer</span></a></li><li id="menu-item-203553" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203553 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-cricket/"><span class="ubermenu-target-title ubermenu-target-text">Cricket</span></a></li><li id="menu-item-203555" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203555 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-rugby/"><span class="ubermenu-target-title ubermenu-target-text">Rugby</span></a></li><li id="menu-item-368016" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-368016 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-golf/"><span class="ubermenu-target-title ubermenu-target-text">Golf</span></a></li><li id="menu-item-203554" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203554 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-other-sport/"><span class="ubermenu-target-title ubermenu-target-text">Other</span></a></li><li id="menu-item-203552" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203552 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-columnists/"><span class="ubermenu-target-title ubermenu-target-text">Columns</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-217263" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-has-children ubermenu-item-217263 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">PHAKAAATHI</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-217263 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-217284" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-217284 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/phakaaathi-news/"><span class="ubermenu-target-title ubermenu-target-text">LOCAL NEWS</span></a></li><li id="menu-item-217289" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-217289 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/phakaaathi-world/"><span class="ubermenu-target-title ubermenu-target-text">international news</span></a></li><li id="menu-item-217283" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-217283 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/phakaaathi-editors-blog/"><span class="ubermenu-target-title ubermenu-target-text">EDITOR&#8217;S BLOG</span></a></li><li id="menu-item-217288" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-217288 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/fan-zone/"><span class="ubermenu-target-title ubermenu-target-text">FAN ZONE</span></a></li><li id="menu-item-217287" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-217287 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/phakaaathi-psl/"><span class="ubermenu-target-title ubermenu-target-text">PSL</span></a></li><li id="menu-item-985451" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-985451 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/phakaaathi-nedbank-cup/"><span class="ubermenu-target-title ubermenu-target-text">Nedbank Cup</span></a></li><li id="menu-item-620339" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-620339 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/mgosi/"><span class="ubermenu-target-title ubermenu-target-text">Mgosi</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-203543" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-has-children ubermenu-item-203543 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">YOUR LIFE</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-203543 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-847489" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847489 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-entertainment/entertainment-celebrities/"><span class="ubermenu-target-title ubermenu-target-text">Celebrities</span></a></li><li id="menu-item-390330" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-390330 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/fitness-and-health-your-life/"><span class="ubermenu-target-title ubermenu-target-text">Fitness and Health</span><span class="ubermenu-target-divider"> – </span><span class="ubermenu-target-description ubermenu-target-text">The Citizen shares health and fitness tips and news</span></a></li><li id="menu-item-397029" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-397029 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/eat-in-out/"><span class="ubermenu-target-title ubermenu-target-text">Food</span></a></li><li id="menu-item-203566" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203566 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-entertainment/"><span class="ubermenu-target-title ubermenu-target-text">Entertainment</span></a></li><li id="menu-item-781112" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-781112 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/ecomobility/"><span class="ubermenu-target-title ubermenu-target-text">Ecomobility</span></a></li><li id="menu-item-345889" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-345889 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-entertainment/soapies/"><span class="ubermenu-target-title ubermenu-target-text">Soapies</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-203544" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-has-children ubermenu-item-203544 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/motoring/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">MOTORING</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-203544 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-203571" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203571 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/motoring/motoring-news/"><span class="ubermenu-target-title ubermenu-target-text">News</span></a></li><li id="menu-item-203572" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203572 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/motoring/motoring-motorsport/"><span class="ubermenu-target-title ubermenu-target-text">Motor Sport</span></a></li><li id="menu-item-207745" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-207745 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" title="NEW CAR PRICE GUIDE" target="_blank" href="http://citizen.co.za/146069/new-car-price-guide-2/"><span class="ubermenu-target-title ubermenu-target-text">NEW CAR PRICE GUIDE</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-203542" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-has-children ubermenu-item-203542 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/horses/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">HORSES</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-203542 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-203562" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203562 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/horses/horses-news/"><span class="ubermenu-target-title ubermenu-target-text">news</span></a></li><li id="menu-item-203561" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-203561 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/horses/horses-columnists/"><span class="ubermenu-target-title ubermenu-target-text">Columns</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-1791" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-has-children ubermenu-item-1791 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/opinion/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">OPINION</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-1791 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-1793" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-1793 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/opinion/opinion-columns/"><span class="ubermenu-target-title ubermenu-target-text">Columns</span></a></li><li id="menu-item-405505" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-405505 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/opinion/opinion-editorials/"><span class="ubermenu-target-title ubermenu-target-text">Editorials</span></a></li><li id="menu-item-408951" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-408951 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/cartoons/"><span class="ubermenu-target-title ubermenu-target-text">Cartoons</span></a></li><li id="menu-item-847519" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847519 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/talking-point/"><span class="ubermenu-target-title ubermenu-target-text">Talking Point</span><span class="ubermenu-target-divider"> – </span><span class="ubermenu-target-description ubermenu-target-text">The Citizen’s readers weigh in on issues affecting us all</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li><li id="menu-item-847453" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-has-children ubermenu-item-847453 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto ubermenu-has-submenu-drop ubermenu-has-submenu-mega" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://auctions.citizen.co.za/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Buy &#038; win</span></a><ul class="ubermenu-submenu ubermenu-submenu-id-847453 ubermenu-submenu-type-auto ubermenu-submenu-type-mega ubermenu-submenu-drop ubermenu-submenu-align-full_width ubermenu-submenu-retractor-top" ><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li><li id="menu-item-847477" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-847477 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" target="_blank" href="http://auctions.citizen.co.za/"><span class="ubermenu-target-title ubermenu-target-text">auctions</span></a></li><li id="menu-item-847459" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-847459 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" target="_blank" href="http://www.citizen.co.za/wp-content/ftp/classifieds/classifieds.pdf?b644a6"><span class="ubermenu-target-title ubermenu-target-text">classifieds</span></a></li><li id="menu-item-854461" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-854461 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/buyinbulk"><span class="ubermenu-target-title ubermenu-target-text">buy in bulk</span></a></li><li id="menu-item-847461" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847461 ubermenu-item-auto ubermenu-item-header ubermenu-item-level-1 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/competitions/"><span class="ubermenu-target-title ubermenu-target-text">Competitions</span></a></li><li class="ubermenu-retractor ubermenu-retractor-mobile"><i class="fa fa-times"></i> Close</li></ul></li></ul></nav>
<!-- End UberMenu -->
                    </div>
                </div>
            </div>
        </div>
                    <!-- This is for the categories/pages that has static submenu(s) -->
            <div class="navigation-container bread-crumb">
                <div class="container">
                    <div class="row">
                        <div class="col-md-12">
                            <ul>
                                                            </ul>
                        </div>
                    </div>
                </div>
            </div>
                    <!-- Header Ends-->
    </div><!--end header-->
    <div class="pagecontent">
        <div id="side-ads-wrapper" class="side-ads-wrapper hidden-sm hidden-xs">

            <!--/* OpenX JavaScript tag */-->

<!-- /*
 * The tag in this template has been generated for use on a
 * non-SSL page. If this tag is to be placed on an SSL page, change the
 * 'http://ox-d.caxton.co.za/...'
 * to
 * 'https://ox-d.caxton.co.za/...'
 */ -->

<script type="text/javascript">
if (!window.OX_ads) { OX_ads = []; }
OX_ads.push({ "auid" : "537131831" });
</script>
<script type="text/javascript">
document.write('<scr'+'ipt src="http://ox-d.caxton.co.za/w/1.0/jstag"><\/scr'+'ipt>');
</script>
<noscript><iframe id="04f2ab41ae" name="04f2ab41ae" src="http://ox-d.caxton.co.za/w/1.0/afr?auid=537131831&cb=INSERT_RANDOM_NUMBER_HERE" frameborder="0" scrolling="no" width="1390" height="800"><a href="http://ox-d.caxton.co.za/w/1.0/rc?cs=04f2ab41ae&cb=INSERT_RANDOM_NUMBER_HERE" ><img src="http://ox-d.caxton.co.za/w/1.0/ai?auid=537131831&cs=04f2ab41ae&cb=INSERT_RANDOM_NUMBER_HERE" border="0" alt=""></a></iframe></noscript>
            <!-- <div style="">
                <img src="https://tpc.googlesyndication.com/simgad/3992018416641721985" style="position: absolute;left: -9999px;right: -9999px;margin: auto;max-width: 1920px!important;width: 2100px;min-width: 2100px;display: block;">
            </div> -->
        </div> <!--end side-ads-wrapper-->
        <div class="container thepage">



<div class="row maincontent" style="margin-top: 10px;">
	<!--start of the right main column-->
	<div class="col-main">

	        		<div id="post-" class="post-153078 post type-post status-publish format-standard has-post-thumbnail hentry category-news-national tag-howard-dembovsky tag-jpsa tag-justice-project-south-africa tag-opposition-to-urban-tolling-alliance tag-outa tag-wayne-duvenage cxt_positions-home-section-1-lead-3">
			<div class="single-cat-header">
        				<span class="single-cat news-national-color">
        					<a href="http://citizen.co.za/category/news/news-national/">National</a>
        				</span>
        				<span class="single-date">1.4.2014 01:50 pm</span>
        			</div>
	        		<h1 class="single-headline">
				Outa claims proof of e-toll mismanagement	        		</h1>
	        		<div class="theshare">
	                  <!-- Go to www.addthis.com/dashboard to customize your tools -->
				      <!--<div class="addthis_sharing_toolbox"></div>-->
				      <div class="addthis_sharing_toolbox" data-url="http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/" data-title="Outa claims proof of e-toll mismanagement"></div>
	                  </div>
	                  				<div class="single-byline">
					Yadhana Jadoo & Alex Mitchley 				</div>
	                  	               		<div class="single-img">
					<img src="http://citizen.co.za/wp-content/uploads/sites/18/2014/01/et13.jpg?b644a6" alt="FILE PICTURE: E-toll objectors gather, 25 January 2014, at the Portuguese Hall in Joburg South, before taking part in a mass protest drive along the tolled highways. Picture: Michel Bega" class="img-responsive"/>
					<!-- <img src="http://citizen.co.za/wp-content/uploads/sites/18/2014/12/063_459985178-526x400.jpg?4cc338&amp;b644a6" class="img-responsive"> -->
					<p class="wp-caption-text">
					FILE PICTURE: E-toll objectors gather, 25 January 2014, at the Portuguese Hall in Joburg South, before taking part in a mass protest drive along the tolled highways. Picture: Michel Bega					</p>
				</div>
	               		                  <h2 class="single-excerpt">
	                  	The Opposition to Urban Tolling Alliance (Outa) has once again pleaded with government to listen to “critics” against e-tolling, in light of new information provided by a whistle blower on the user payment system.
	                  </h2>
	                  <div class="single-content">
				<p><span style="line-height: 1.5em">This, as Outa awaits feedback from the Public Protector’s office on a complaint it laid, following “damning” information it received from a source within the system.</span></p>
<p><a href="http://www.citypress.co.za/news/whistleblower-worked-sanral-tells-thuli-madonsela-e-tolls/" target="_blank"><em>City Press</em> reported</a> on Sunday that an employee of Austrian Company Kapsch &#8211; used to design the e-toll system &#8211; had warned the SA National Roads Agency Ltd (Sanral) of the high risk in the implementation of a national roll-out.</p>
<p>He said the e-tolling system was designed to monitor 7 000 km of national roads, with tolls being planned for Durban and Cape Town, it reported.</p>
<p>The source further stated that there were design flaws within the system and Sanral’s control centre in Midrand had been created to monitor all roads in South Africa.</p>
<p>If the claims are true, it suggests that Sanral saw the Gauteng highway tolling project as either a starting point for national e-tolling, or it significantly over-invested in a system it did not need.</p>
<p>Sanral spokesman Vusi Mona, in rejecting the allegations by the &#8220;so-called informant&#8221;, said the Public Protector Thuli Madonsela had not yet contacted the entity.</p>
<p>It would however &#8220;co-operate&#8221;, should her office conduct an investigation, he added.</p>
<p>Mona said Sanral and its concessionaires were in the process of installing the &#8220;electronic toll collection equipment&#8221; needed at conventional toll plazas across the country.</p>
<p>It would make the exact details as to which toll plazas and  when this payment method will be available, at an &#8220;opportune time&#8221;.</p>
<p>&#8220;Electronic toll collection &#8211; the use of e-tags &#8211; is a method of payment for one’s toll fees. Electronic toll collection does not replace existing toll plazas. It is a tool that toll plazas will use in addition to current methods of payment.</p>
<p>&#8220;By obtaining and e-tag and registering it, e-tolling allows an account holder to use the same e-tag and e-toll account to pay toll fees at any toll plaza equipped to accept e-tags.&#8221;</p>
<p>Deputy Public Protector Kevin Malunga, who was handling the complaint, according to Outa, was not immediately available for comment.</p>
<p>Outa chairman Wayne Duvenage told <em>The Citizen</em> that the alliance had always provided an open door for Parliament’s Portfolio Committee on Transport and Government’s Inter-Ministerial Committee (IMC), which previously engaged with stakeholders against e-tolling, prior to its implementation.</p>
<p>It was important for government to learn from its critics, said Duvenage.</p>
<p>“… And they are not learning from their critics. We are happy to present to anybody.”</p>
<p>He described previous IMC engagements as being unfruitful with government unwilling to unpack and explore the rationality of arguments.</p>
<p>The insider has described “them as arrogant and dangerous people who steam-roll public opinion … bully politicians, and business people and do not act in the interests of the country”, according to Outa.</p>
<p>Duvenage hailed the disclosures as a breakthrough which he hoped would start laying the table for “meaningful multi-lateral engagement with all stakeholders to transcend the mess”.</p>
<p>“The whistle blower shows the sheer arrogance of the system.”</p>
<p>He further asked motorists not the “fall” for a system which was not working.</p>
<p>“The compliance levels are far too low. Don’t be hoodwinked by the propaganda. Now the chickens are coming out to roost.”</p>
<p>Justice Project South Africa (JPSA) chairperson Howard Dembovsky said it was only a matter of time until someone with a “paining conscious” came forward.</p>
<p>“This is a very good thing, we need more people to tell the truth behind what has happened and what is happening with the e-tolls,” said Dembovsky.</p>
<p>The JPSA is convinced that there is corruption behind the controversial system: “It will come out in the dirty washing, a system rolled out veiled in shrouds of secrecy is a dead giveaway.”</p>
<p>Dembovsky echoed Duvenage’s comments, indicating that further IMC engagements would be “a waste of time”.</p>
<p>“The last round of engagements was just Sanral telling people what was going to happen. Do not waste more time and our money,” he said.</p>
<p>“Take the money and lets have a referendum, this is after all a democracy and we have not held a single referendum on the matter,” said Dembovsky.</p>
<p>“Let’s do it, let’s show what democracy is all about,” he added.</p>
<p>&nbsp;</p>

	                  </div>
	                  <div class="single-social-share">
				          <!-- Go to www.addthis.com/dashboard to customize your tools -->
				          <div class="addthis_jumbo_share" data-url="http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/" data-title="Outa claims proof of e-toll mismanagement"></div>
	                  </div>
	                  	<div class="related-articles col-sm-12">
	         <h5 class="related-articles-title">Related Stories</h5>
		

		<div class="related-item">
			<span class="related-article-item">
				<a href="http://citizen.co.za/984741/outa-warns-e-toll-sms-demands-are-illegal/" rel="bookmark" title="Link to Outa warns e-toll sms demands are ‘íllegal’">
					Outa warns e-toll sms demands are ‘íllegal’				</a>
			</span>
			<span class="related-article-date">
				10.2.2016			</span>
		</div>
		

		<div class="related-item">
			<span class="related-article-item">
				<a href="http://citizen.co.za/972919/outa-to-tackle-electricity-prices-now/" rel="bookmark" title="Link to Outa to tackle electricity prices now">
					Outa to tackle electricity prices now				</a>
			</span>
			<span class="related-article-date">
				2.2.2016			</span>
		</div>
		

		<div class="related-item">
			<span class="related-article-item">
				<a href="http://citizen.co.za/971221/outa-now-the-peoples-public-protector/" rel="bookmark" title="Link to VIDEO: Outa now the ‘people’s public protector’">
					VIDEO: Outa now the ‘people’s public protector’				</a>
			</span>
			<span class="related-article-date">
				1.2.2016			</span>
		</div>
			</div>
	                  <div class="comments">
	                  	
	<!-- Here we load disqus comments -->
	<div class="dcl-disqus-thread" id="comments" >
	<div id="disqus_thread">
				
	
			</div>
	</div>
	
		
			<script type="text/javascript">
	/* <![CDATA[ */
		var disqus_url = 'http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/';
		var disqus_identifier = '153078 http://citizen.co.za/?p=153078';
		var disqus_container_id = 'disqus_thread';
		var disqus_domain = 'disqus.com';
		var disqus_shortname = 'thecitizenza';
		var disqus_title = "Outa claims proof of e-toll mismanagement";
		var disqus_config = function () {
			var config = this; // Access to the config object
			config.language = '';

			/* Add the ability to add javascript callbacks */
			
			/*
			   All currently supported events:
				* preData — fires just before we request for initial data
				* preInit - fires after we get initial data but before we load any dependencies
				* onInit  - fires when all dependencies are resolved but before dtpl template is rendered
				* afterRender - fires when template is rendered but before we show it
				* onReady - everything is done
			 */

			config.callbacks.preData.push(function() {
				// clear out the container (its filled for SEO/legacy purposes)
				document.getElementById(disqus_container_id).innerHTML = '';
			});
this.page.api_key = '53n602jMXOB2dwuoJ5GlY4IsHpRzTxn9Krtw3dQZd7mwVyBlBsiKpyACf2hFCmpG';
this.sso = {     
          name: "The Citizen",       
          button: "http://citizen.co.za/wp-content/uploads/sites/18/2014/12/citizen-disqus-logo1.png",       
          url: "http://citizen.co.za/wp-login.php",        
          logout: "http://citizen.co.za/wp-login.php?action=logout",       
          width: "800",        
          height: "700"        
    };		};
	/* ]]> */
	</script>
	
		
	<script type="text/javascript">
	/* <![CDATA[ */
		var DsqLocal = {
			'trackbacks': [
				],
			'trackback_url': "http:\/\/citizen.co.za\/153078\/outa-claims-proof-e-toll-mismanagement\/trackback\/"		};
	/* ]]> */
	</script>
				                  </div>
        		</div>
        		</div>
	<div class="col-sidebar">
	
	    <!--/* OpenX JavaScript tag */-->

        <!-- /*
         * The tag in this template has been generated for use on a
         * non-SSL page. If this tag is to be placed on an SSL page, change the
         * 'http://ox-d.caxton.co.za/...'
         * to
         * 'https://ox-d.caxton.co.za/...'
         */ -->
        
        <script type="text/javascript">
          if (!window.OX_ads) { OX_ads = []; }
          OX_ads.push({ "auid" : "459170" });
        </script>
        
        <script type="text/javascript">
           document.write('<scr'+'ipt src="http://ox-d.caxton.co.za/w/1.0/jstag"><\/scr'+'ipt>');
        </script>
        
        <noscript><iframe id="eefb1f3cbb" name="eefb1f3cbb" src="http://ox-d.caxton.co.za/w/1.0/afr?auid=459170&cb=INSERT_RANDOM_NUMBER_HERE" frameborder="0" scrolling="no" width="300" height="250"><a href="http://ox-d.caxton.co.za/w/1.0/rc?cs=eefb1f3cbb&cb=INSERT_RANDOM_NUMBER_HERE" ><img src="http://ox-d.caxton.co.za/w/1.0/ai?auid=459170&cs=eefb1f3cbb&cb=INSERT_RANDOM_NUMBER_HERE" border="0" alt=""></a></iframe></noscript>
         
	
    <!--/* OpenX JavaScript tag */-->

    <!-- /*
     * The tag in this template has been generated for use on a
     * non-SSL page. If this tag is to be placed on an SSL page, change the
     * 'http://ox-d.caxton.co.za/...'
     * to
     * 'https://ox-d.caxton.co.za/...'
    */ -->

    <script type="text/javascript">
      if (!window.OX_ads) { OX_ads = []; }
      OX_ads.push({ "auid" : "537079555" });
    </script>

    <script type="text/javascript">
      document.write('<scr'+'ipt src="http://ox-d.caxton.co.za/w/1.0/jstag"><\/scr'+'ipt>');
    </script>
    <br/>
    <noscript><iframe id="d1d0a21601" name="d1d0a21601" src="http://ox-d.caxton.co.za/w/1.0/afr?auid=537079555&cb=INSERT_RANDOM_NUMBER_HERE" frameborder="0" scrolling="no" width="300" height="600"><a href="http://ox-d.caxton.co.za/w/1.0/rc?cs=d1d0a21601&cb=INSERT_RANDOM_NUMBER_HERE" ><img src="http://ox-d.caxton.co.za/w/1.0/ai?auid=537079555&cs=d1d0a21601&cb=INSERT_RANDOM_NUMBER_HERE" border="0" alt=""></a></iframe></noscript>
    <br/>
	<div class="connect_phakaaathi">
		<div class="sidebar-connect greyscale-banner" style="border-bottom: 1px #ccc solid; border-top: 1px #ccc solid; padding-bottom:10px; padding-top:10px;">
			<a href="http://connect.citizen.co.za" title="Connect Youth Website" onClick="ga('send', 'event', 'Site links', 'Click', 'Connect Links on Citizen', {'nonInteraction': 1});">
				<img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/connect-greyscale.jpg?b644a6" alt="Connect Youth Website" class="img-responsive greyscale-img">
				<img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/connect-banner.jpg?b644a6" alt="Connect Youth Website" class="img-responsive normal-img">
			</a>
		</div>

		<div class="sidebar-phakaaathi greyscale-banner" style="margin-bottom: 20px; padding-bottom: 10px;">
			<a href="http://citizen.co.za/category/phakaaathi/" title="Phakaaathi - More Soccer. Your Way." onClick="ga('send', 'event', 'Phakaaathi link', 'Click', 'Phakaaathi Links on Citizen', {'nonInteraction': 1});">
				<img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/phakaaathi-greyscale.jpg?b644a6" class="img-responsive greyscale-img">
				<img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/phakaaathi-banner.jpg?b644a6" class="img-responsive normal-img">
			</a>
		</div>
	</div><!--end of connect_phakaaathi-->
	<div class="whats-hot">
		<h4 class="hot-title">what's hot</h4>


		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/999226/chiefs-and-sundowns-target-extends-stars-stay/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2015/10/TL_1124926.jpg?b644a6" alt="Chiefs and Sundowns target extends Stars stay" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat mgosi-color">
						<a href="http://citizen.co.za/category/phakaaathi/mgosi/">
							Phakaaathi						</a>
					</span>
					<h4 class="hot-headline"><a href="http://citizen.co.za/999226/chiefs-and-sundowns-target-extends-stars-stay/" title="Link to Chiefs and Sundowns target extends Stars stay">Chiefs and Sundowns target extends Stars stay</a></h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->

		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/999234/mbesuma-wary-of-bucs-threat/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2016/01/B15J1SM0097-168x112.jpg?b644a6" alt="Mbesuma wary of Bucs threat" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat phakaaathi-news-color">
						<a href="http://citizen.co.za/category/phakaaathi/phakaaathi-news/">
							Phakaaathi						</a>
					</span>
					<h4 class="hot-headline"><a href="http://citizen.co.za/999234/mbesuma-wary-of-bucs-threat/" title="Link to Mbesuma wary of Bucs threat">Mbesuma wary of Bucs threat</a></h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->

		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/999210/maluleka-i-havent-been-at-my-best/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2016/02/B16A4SM0754-168x112.jpg?b644a6" alt="Maluleka – I haven’t been at my best" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat phakaaathi-news-color">
						<a href="http://citizen.co.za/category/phakaaathi/phakaaathi-news/">
							Phakaaathi						</a>
					</span>
					<h4 class="hot-headline"><a href="http://citizen.co.za/999210/maluleka-i-havent-been-at-my-best/" title="Link to Maluleka – I haven’t been at my best">Maluleka – I haven’t been at my best</a></h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->

		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/999056/f1-williams-unveil-new-car-looking-to-challenge-the-best/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2016/02/williams-f1-fw38_3418119-168x112.jpg?b644a6" alt="F1: Williams unveil new car looking to challenge the best" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat motoring-motorsport-color">
						<a href="http://citizen.co.za/category/motoring/motoring-motorsport/">
							Motorsport						</a>
					</span>
					<h4 class="hot-headline"><a href="http://citizen.co.za/999056/f1-williams-unveil-new-car-looking-to-challenge-the-best/" title="Link to F1: Williams unveil new car looking to challenge the best">F1: Williams unveil new car looking to challenge the best</a></h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->

		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/999020/ea-lla-kotos-confidence-soars/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2016/02/B16A4SS0052-168x112.jpg?b644a6" alt="Ea Lla Koto&#8217;s confidence soars" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat phakaaathi-news-color">
						<a href="http://citizen.co.za/category/phakaaathi/phakaaathi-news/">
							Phakaaathi						</a>
					</span>
					<h4 class="hot-headline"><a href="http://citizen.co.za/999020/ea-lla-kotos-confidence-soars/" title="Link to Ea Lla Koto&#8217;s confidence soars">Ea Lla Koto&#8217;s confidence soars</a></h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->
	</div><!--end of whats hot-->
	<div class="whats-hot">
		<h4 class="hot-title">readers' choice</h4>
		
		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/997716/is-aka-richer-than-cassper-nyovest/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2015/09/ED_0070580.jpg?b644a6" alt="Is AKA richer than Cassper Nyovest?" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat entertainment-celebrities-color">
						<a href="http://citizen.co.za/category/your-life/your-life-entertainment/entertainment-celebrities/">
							Celebrities						</a>
					</span>
					<h4 class="hot-headline">
						<a href="http://citizen.co.za/997716/is-aka-richer-than-cassper-nyovest/" title="Link to Is AKA richer than Cassper Nyovest?"> Is AKA richer than Cassper Nyovest?</a>
					</h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->
		
		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/994925/where-zcc-finances-come-from/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2016/02/000033635-168x112.jpg?b644a6" alt="Where ZCC finances come from" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat news-national-color">
						<a href="http://citizen.co.za/category/news/news-national/">
							National						</a>
					</span>
					<h4 class="hot-headline">
						<a href="http://citizen.co.za/994925/where-zcc-finances-come-from/" title="Link to Where ZCC finances come from"> Where ZCC finances come from</a>
					</h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->
		
		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/995938/bonang-goes-big-in-la/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2014/05/0000207033.jpg?b644a6" alt="Bonang goes big in LA" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat entertainment-celebrities-color">
						<a href="http://citizen.co.za/category/your-life/your-life-entertainment/entertainment-celebrities/">
							Celebrities						</a>
					</span>
					<h4 class="hot-headline">
						<a href="http://citizen.co.za/995938/bonang-goes-big-in-la/" title="Link to Bonang goes big in LA"> Bonang goes big in LA</a>
					</h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->
		
		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/996098/joemat-pettersson-lays-into-malema/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2016/01/0000232234-168x112.jpg?b644a6" alt="Joemat-Pettersson lays into Malema" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat news-national-color">
						<a href="http://citizen.co.za/category/news/news-national/">
							National						</a>
					</span>
					<h4 class="hot-headline">
						<a href="http://citizen.co.za/996098/joemat-pettersson-lays-into-malema/" title="Link to Joemat-Pettersson lays into Malema"> Joemat-Pettersson lays into Malema</a>
					</h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->
		
		<div class="hot-article">
			<div class="row">
				<div class="col-xs-5 thumb">
					<a href="http://citizen.co.za/995998/ukzn-src-president/">
						<img src="http://citizen.co.za/wp-content/uploads/sites/18/2015/10/UKZN-12.png?b644a6" alt="Security ‘shoots’ UKZN SRC president" class="img-responsive"/>
					</a>
				</div>
				<div class="col-xs-7">
					<span class="hot-cat news-national-color">
						<a href="http://citizen.co.za/category/news/news-national/">
							National						</a>
					</span>
					<h4 class="hot-headline">
						<a href="http://citizen.co.za/995998/ukzn-src-president/" title="Link to Security ‘shoots’ UKZN SRC president"> Security ‘shoots’ UKZN SRC president</a>
					</h4>
				</div>
			</div><!--end row-->
		</div><!--end hot-article-->
			</div><!--end of whats hot-->

	    <!--/* OpenX JavaScript tag */-->

        <!-- /*
         * The tag in this template has been generated for use on a
         * non-SSL page. If this tag is to be placed on an SSL page, change the
         * 'http://ox-d.caxton.co.za/...'
         * to
         * 'https://ox-d.caxton.co.za/...'
         */ -->
        
        <script type="text/javascript">
          if (!window.OX_ads) { OX_ads = []; }
          OX_ads.push({ "auid" : "538211890" });
        </script>
        
        <script type="text/javascript">
           document.write('<scr'+'ipt src="http://ox-d.caxton.co.za/w/1.0/jstag"><\/scr'+'ipt>');
        </script>
        
        <noscript><iframe id="36d2fd6569" name="36d2fd6569" src="http://ox-d.caxton.co.za/w/1.0/afr?auid=538211890&cb=INSERT_RANDOM_NUMBER_HERE" frameborder="0" scrolling="no" width="300" height="250"><a href="http://ox-d.caxton.co.za/w/1.0/rc?cs=36d2fd6569&cb=INSERT_RANDOM_NUMBER_HERE" ><img src="http://ox-d.caxton.co.za/w/1.0/ai?auid=538211890&cs=36d2fd6569&cb=INSERT_RANDOM_NUMBER_HERE" border="0" alt=""></a></iframe></noscript>
         
	
    <!--/* OpenX JavaScript tag */-->

    <!-- /*
     * The tag in this template has been generated for use on a
     * non-SSL page. If this tag is to be placed on an SSL page, change the
     * 'http://ox-d.caxton.co.za/...'
     * to
     * 'https://ox-d.caxton.co.za/...'
    */ -->

    <script type="text/javascript">
       if (!window.OX_ads) { OX_ads = []; }
       OX_ads.push({ "auid" : "538211889" });
    </script>
    
    <script type="text/javascript">
       document.write('<scr'+'ipt src="http://ox-d.caxton.co.za/w/1.0/jstag"><\/scr'+'ipt>');
    </script>
    <br/>
    <noscript><iframe id="d4274c71da" name="d4274c71da" src="http://ox-d.caxton.co.za/w/1.0/afr?auid=538211889&cb=INSERT_RANDOM_NUMBER_HERE" frameborder="0" scrolling="no" width="300" height="600"><a href="http://ox-d.caxton.co.za/w/1.0/rc?cs=d4274c71da&cb=INSERT_RANDOM_NUMBER_HERE" ><img src="http://ox-d.caxton.co.za/w/1.0/ai?auid=538211889&cs=d4274c71da&cb=INSERT_RANDOM_NUMBER_HERE" border="0" alt=""></a></iframe></noscript>
    <br/>
	<!-- <div class="whats-hot"> -->
		<!-- <h4 class="hot-title">Results</h4> -->
		
		<script type="text/javascript">
		 	var OX_ads = OX_ads || [];
		 	OX_ads.push({
		 	 	slot_id: "538151272_INSERT_SLOT_ID_HERE",
		 	 	auid: "538151272"
		 	 });
		 </script>

		 <div id="538151272_INSERT_SLOT_ID_HERE" style="width:300px;height:30px;margin:0;padding:0">
			 <noscript><iframe id="a6c3035eb2" name="a6c3035eb2" src="http://ox-d.caxton.co.za/w/1.0/afr?auid=538151272&cb=INSERT_RANDOM_NUMBER_HERE" frameborder="0" scrolling="no" width="300" height="30"><a href="http://ox-d.caxton.co.za/w/1.0/rc?cs=a6c3035eb2&cb=INSERT_RANDOM_NUMBER_HERE" ><img src="http://ox-d.caxton.co.za/w/1.0/ai?auid=538151272&cs=a6c3035eb2&cb=INSERT_RANDOM_NUMBER_HERE" border="0" alt=""></a></iframe></noscript>
		 </div> 


		 <script>
			jQuery(document).ready(function(){
			   document.getElementById('jse-iframe').innerHTML = '<iframe src="http://www.profiledata.co.za/brokersites/citizen/markets.aspx?tab=jse" width="290" height="275" scrolling="no" frameborder="0"></iframe>';
			   document.getElementById('currencies-iframe').innerHTML = '<iframe src="http://www.profiledata.co.za/brokersites/citizen/markets.aspx?tab=cur" width="290" height="275" scrolling="no" frameborder="0"></iframe>';
			   document.getElementById('commodities-iframe').innerHTML = '<iframe src="http://www.profiledata.co.za/brokersites/citizen/markets.aspx?tab=com" width="290" height="275" scrolling="no" frameborder="0"></iframe>';
			});
		</script>
		<div class="row">
                  	<div class="col-lg-12 col-md-12 col-sm-12 col-xs-12 financial-data">
                  		<ul class="nav nav-tabs" role="tablist">
                  			<li role="presentation" class="active"><a href="#jse" aria-controls="jse" role="tab" data-toggle="tab">JSE</a></li>
                  			<li role="presentation"><a href="#currencies" aria-controls="currencies" role="tab" data-toggle="tab">Currencies</a></li>
                  			<li role="presentation"><a href="#commodities" aria-controls="commodities" role="tab" data-toggle="tab">Commodities</a></li>
                  		</ul>

                  		<div class="tab-content">
    					<div role="tabpanel" class="tab-pane active" id="jse">
    						<div id="jse-iframe" class="widget-body">
                					</div>
    					</div>
    					<div role="tabpanel" class="tab-pane" id="currencies">
    						<div id="currencies-iframe" class="widget-body">
                					</div>
    					</div>
    					<div role="tabpanel" class="tab-pane" id="commodities">
    						<div id="commodities-iframe" class="widget-body">
                					</div>
    					</div>
				</div>
	                  </div>
                  </div>
	<!-- </div> -->
	<div class="whats-hot">
		<h4 class="hot-title">poll</h4>
		
                <div class='gf_browser_chrome gform_wrapper gpoll_enabled gpoll_show_results_link gpoll_wrapper' id='gform_wrapper_782' ><form method='post' enctype='multipart/form-data'  id='gform_782' class='gpoll_enabled gpoll_show_results_link gpoll' action='/153078/outa-claims-proof-e-toll-mismanagement/'>
                        <div class='gform_body'><ul id='gform_fields_782' class='gform_fields top_label form_sublabel_below description_below'><li id='field_782_1' class='gfield field_sublabel_below field_description_below gpoll_field' ><label class='gfield_label'  >What are your thoughts on the CRL commission’s involvement in religious institutions’ finances?</label><div class='ginput_container ginput_container_radio'><ul class='gfield_radio' id='input_782_1'><li class='gchoice_782_1_0'><input name='input_1' type='radio' value='gpoll1419b3464'  id='choice_782_1_0' tabindex='1'    /><label for='choice_782_1_0' id='label_782_1_0'>It’s fine. Religious institutions need money to survive.</label></li><li class='gchoice_782_1_1'><input name='input_1' type='radio' value='gpoll136b3efea'  id='choice_782_1_1' tabindex='2'    /><label for='choice_782_1_1' id='label_782_1_1'>I support the Commission. Some religious organisations take advantage of the poor.</label></li><li class='gchoice_782_1_2'><input name='input_1' type='radio' value='gpoll14f5b7f4e'  id='choice_782_1_2' tabindex='3'    /><label for='choice_782_1_2' id='label_782_1_2'>I don’t believe that religion can be regulated.</label></li></ul></div></li>
                            </ul></div>
        <div class='gform_footer top_label'> <input type='submit' id='gform_submit_button_782' class='gform_button button' value='Submit' tabindex='4' onclick='if(window["gf_submitting_782"]){return false;}  window["gf_submitting_782"]=true;  ' /> 
            <input type='hidden' class='gform_hidden' name='is_submit_782' value='1' />
            <input type='hidden' class='gform_hidden' name='gform_submit' value='782' />
            
            <input type='hidden' class='gform_hidden' name='gform_unique_id' value='' />
            <input type='hidden' class='gform_hidden' name='state_782' value='WyJbXSIsIjU0Mzk5ZWQ3N2QxMTkyMTcxNmJlOTc0ZTdjMTQzMzY4Il0=' />
            <input type='hidden' class='gform_hidden' name='gform_target_page_number_782' id='gform_target_page_number_782' value='0' />
            <input type='hidden' class='gform_hidden' name='gform_source_page_number_782' id='gform_source_page_number_782' value='1' />
            <input type='hidden' name='gform_field_values' value='' />
            
        </div>
                        </form>
                        </div><script type='text/javascript'> jQuery(document).bind('gform_post_render', function(event, formId, currentPage){if(formId == 782) {} } );jQuery(document).bind('gform_post_conditional_logic', function(event, formId, fields, isInit){} );</script><script type='text/javascript'> jQuery(document).ready(function(){jQuery(document).trigger('gform_post_render', [782, 1]) } ); </script>
	</div>
	<div class="whats-hot today-edition">
		<h4 class="hot-title">today in print</h4>
		<script>
		jQuery(document).ready(function(){
   		jQuery(".press-dispay-home").css({"background-image":"url(http://www.pressdisplay.com/advertising/showimage.aspx?cid=9674&type=thumb120)","background-repeat":"no-repeat","background-position":"22px 30px"});
		});
		</script>
		<!-- end pulling and assigning the pressdisplay image -->
                  <div class="press-dispay-home">
                           <a href="http://e-edition.citizen.co.za" title="The Citizen Today in Print" target="_blank" onClick="ga('send', 'event', 'E-Edition Links', 'Click', 'E-Edition Clickthrough', {'nonInteraction': 1});">
                                	<img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/transperant.png?b644a6"
                                    	title="Read today's edition"
                                        alt="Read Today's edition">
                           </a>
                  </div>
	</div>
	</div><!--end col-sidebar-->
</div>
</div><!--end thepage-->
</div><!--end pagecontent-->
<div class="footer">
    <!-- Back to the top button -->
    <a href="#home" class="back_to_top" id="back-to-top"><span class="fa fa-angle-up"></span></a>

    <!-- Primary menu starts -->
    <div class="footer-primary">
        <div class="container">
            <div class="row">
                <div class="col-md-12">
                    <ul>
                        
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol8] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol8 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-334-sitemapcol8"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-334-sitemapcol8" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-334 ubermenu-loc-sitemapcol8 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-334-sitemapcol8" class="ubermenu-nav"><li id="menu-item-3929" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-3929 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/contact-us/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Contact us</span></a></li><li id="menu-item-4284" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-4284 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/about-us/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">About us</span></a></li><li id="menu-item-3928" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-3928 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/code-of-conduct/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Code of Conduct</span></a></li><li id="menu-item-3930" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-3930 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/terms-of-use/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Privacy Policy</span></a></li><li id="menu-item-317112" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-317112 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/advertising/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Advertising Rate Card</span></a></li></ul></nav>
<!-- End UberMenu -->
                    </ul>
                </div>
            </div>
        </div>
    </div>
    <!-- Primary menu ends -->
    <!-- Secondary menu starts -->
    <div class="footer-secondary">
        <div class="container">
            <div class="row">

                <!-- hide division footer-navigation-hide-on-mobile when a view is mobile -->
                <div class="col-md-12 footer-navigation-hide-on-mobile">
                    <div class="row">
                        <p></p>
                        <div class="col-md-2">
                            <h4>News</h4>
                            <ul>
                                
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol1] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol1 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-307-sitemapcol1"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-307-sitemapcol1" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-307 ubermenu-loc-sitemapcol1 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-307-sitemapcol1" class="ubermenu-nav"><li id="menu-item-3693" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-current-post-ancestor ubermenu-current-menu-parent ubermenu-current-post-parent ubermenu-item-3693 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-national/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">National</span></a></li><li id="menu-item-3695" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3695 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-africa/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Africa</span></a></li><li id="menu-item-3692" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3692 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-world/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">World</span></a></li><li id="menu-item-424856" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-424856 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-national/news-load-shading/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Load Shedding</span></a></li><li id="menu-item-893437" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-893437 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/news/news-eish/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Eish!</span></a></li></ul></nav>
<!-- End UberMenu -->
                            </ul>
                        </div>
                        <div class="col-md-2 col-xs-2 col-sm-2">
                            <h4>Opinion</h4>
                            <ul>
                                
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol2] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol2 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-308-sitemapcol2"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-308-sitemapcol2" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-308 ubermenu-loc-sitemapcol2 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-308-sitemapcol2" class="ubermenu-nav"><li id="menu-item-3698" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3698 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/opinion/opinion-columns/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Columns</span></a></li><li id="menu-item-3699" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3699 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/opinion/opinion-editorials/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Editorials</span></a></li><li id="menu-item-847621" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847621 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/opinion/cartoons/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Cartoons</span></a></li><li id="menu-item-848415" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-848415 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/talking-point/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Talking Point</span></a></li></ul></nav>
<!-- End UberMenu -->
                            </ul>
                        </div>
                        <div class="col-md-2">
                            <h4>Sport</h4>
                            <ul>
                                
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol3] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol3 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-309-sitemapcol3"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-309-sitemapcol3" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-309 ubermenu-loc-sitemapcol3 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-309-sitemapcol3" class="ubermenu-nav"><li id="menu-item-3713" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3713 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-columnists/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Columns</span></a></li><li id="menu-item-3714" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3714 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-cricket/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Cricket</span></a></li><li id="menu-item-3715" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3715 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-other-sport/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Other</span></a></li><li id="menu-item-3716" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3716 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-rugby/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Rugby</span></a></li><li id="menu-item-847625" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847625 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/phakaaathi/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Soccer</span></a></li><li id="menu-item-847627" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847627 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/sport/sport-golf/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Golf</span></a></li></ul></nav>
<!-- End UberMenu -->
                            </ul>
                        </div>
                        <div class="col-md-2">
                            <h4>Horses</h4>
                            <ul>
                                
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol4] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol4 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-310-sitemapcol4"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-310-sitemapcol4" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-310 ubermenu-loc-sitemapcol4 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-310-sitemapcol4" class="ubermenu-nav"><li id="menu-item-3706" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3706 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/horses/horses-columnists/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Columnists</span></a></li><li id="menu-item-3709" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3709 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/horses/horses-news/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Racing News</span></a></li></ul></nav>
<!-- End UberMenu -->
                            </ul>
                        </div>
                        <div class="col-md-2">
                            <h4>Your life</h4>
                            <ul>
                                
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol5] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol5 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-311-sitemapcol5"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-311-sitemapcol5" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-311 ubermenu-loc-sitemapcol5 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-311-sitemapcol5" class="ubermenu-nav"><li id="menu-item-847631" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847631 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-entertainment/entertainment-celebrities/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Celebrities</span></a></li><li id="menu-item-3726" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3726 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-things-to-do/your-life-food-and-drinks/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Food</span></a></li><li id="menu-item-847641" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847641 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-style/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">style</span></a></li><li id="menu-item-3723" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3723 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-entertainment/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Entertainment</span></a></li><li id="menu-item-847643" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-847643 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/your-life/your-life-entertainment/soapies/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Soapies</span></a></li></ul></nav>
<!-- End UberMenu -->
                            </ul>
                        </div>
                        <div class="col-md-2">
                            <h4>Motoring</h4>
                            <ul>
                                
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol6] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol6 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-69560-sitemapcol6"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-69560-sitemapcol6" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-69560 ubermenu-loc-sitemapcol6 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-69560-sitemapcol6" class="ubermenu-nav"><li id="menu-item-3705" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3705 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/motoring/motoring-news/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Motoring News</span></a></li><li id="menu-item-3702" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3702 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/motoring/motoring-car-tests-and-new-models/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">features</span></a></li><li id="menu-item-3703" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-3703 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/motoring/motoring-motorsport/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Motorsport</span></a></li><li id="menu-item-847649" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-847649 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/146069/new-car-price-guide-2/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">new price guide</span></a></li><li id="menu-item-870573" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-870573 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/motoring/top-tips/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">top tips</span></a></li></ul></nav>
<!-- End UberMenu -->
                            </ul>
                        </div>
                        <div class="col-md-2">
                            <h4>Other</h4>
                            <ul>
                                
<!-- UberMenu [Configuration:main] [Theme Loc:sitemapCol7] [Integration:auto] -->
<a class="ubermenu-responsive-toggle ubermenu-responsive-toggle-main ubermenu-skin-none ubermenu-loc-sitemapcol7 ubermenu-responsive-toggle-content-align-left ubermenu-responsive-toggle-align-full " data-ubermenu-target="ubermenu-main-312-sitemapcol7"><i class="fa fa-bars"></i>menu</a><nav id="ubermenu-main-312-sitemapcol7" class="ubermenu ubermenu-nojs ubermenu-main ubermenu-menu-312 ubermenu-loc-sitemapcol7 ubermenu-responsive ubermenu-responsive-default ubermenu-responsive-collapse ubermenu-horizontal ubermenu-transition-slide ubermenu-trigger-hover_intent ubermenu-skin-none  ubermenu-bar-align-full ubermenu-items-align-left ubermenu-bound ubermenu-sub-indicators ubermenu-retractors-responsive"><ul id="ubermenu-nav-main-312-sitemapcol7" class="ubermenu-nav"><li id="menu-item-317663" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-317663 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" target="_blank" href="http://auctions.citizen.co.za/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Auctions</span></a></li><li id="menu-item-272697" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-272697 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" target="_blank" href="http://citizen.co.za/classifieds" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Classifieds</span></a></li><li id="menu-item-17482" class="ubermenu-item ubermenu-item-type-taxonomy ubermenu-item-object-category ubermenu-item-17482 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/category/competitions/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Competitions</span></a></li><li id="menu-item-319273" class="ubermenu-item ubermenu-item-type-custom ubermenu-item-object-custom ubermenu-item-319273 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" target="_blank" href="http://connect.citizen.co.za/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Connect</span></a></li><li id="menu-item-4957" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-4957 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/about-us/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">About us</span></a></li><li id="menu-item-4958" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-4958 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/code-of-conduct/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Code of Conduct</span></a></li><li id="menu-item-4959" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-4959 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/contact-us/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Contact us</span></a></li><li id="menu-item-4960" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-4960 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/terms-of-use/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Privacy Policy</span></a></li><li id="menu-item-30973" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-30973 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" href="http://citizen.co.za/jobs-at-the-citizen/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Jobs at The Citizen</span></a></li><li id="menu-item-317664" class="ubermenu-item ubermenu-item-type-post_type ubermenu-item-object-page ubermenu-item-317664 ubermenu-item-level-0 ubermenu-column ubermenu-column-auto" ><a class="ubermenu-target ubermenu-item-layout-default ubermenu-item-layout-text_only" title="Advertising Rate Card" href="http://citizen.co.za/advertising/" tabindex="0"><span class="ubermenu-target-title ubermenu-target-text">Advertising Rate Card</span></a></li></ul></nav>
<!-- End UberMenu -->
                            </ul>
                        </div>
                    </div>
                </div>

                <!-- show division footer-navigation-hide-on-mobile when a view is mobile -->
                <div class="col-md-12 footer-navigation-show-on-mobile">
                    <div class="row">
                        <ul>
                            <div class="menu-footer-navigation-container"><ul id="menu-footer-navigation" class="menu"><li id="menu-item-847887" class="menu-item menu-item-type-taxonomy menu-item-object-category current-post-ancestor menu-item-847887"><a href="http://citizen.co.za/category/news/">News</a></li>
<li id="menu-item-847881" class="menu-item menu-item-type-taxonomy menu-item-object-category menu-item-847881"><a href="http://citizen.co.za/category/business/">Business</a></li>
<li id="menu-item-847893" class="menu-item menu-item-type-taxonomy menu-item-object-category menu-item-847893"><a href="http://citizen.co.za/category/sport/">Sport</a></li>
<li id="menu-item-847891" class="menu-item menu-item-type-taxonomy menu-item-object-category menu-item-847891"><a href="http://citizen.co.za/category/phakaaathi/">Phakaaathi</a></li>
<li id="menu-item-847889" class="menu-item menu-item-type-taxonomy menu-item-object-category menu-item-847889"><a href="http://citizen.co.za/category/opinion/">Opinion</a></li>
<li id="menu-item-847885" class="menu-item menu-item-type-taxonomy menu-item-object-category menu-item-847885"><a href="http://citizen.co.za/category/motoring/">Motoring</a></li>
<li id="menu-item-847895" class="menu-item menu-item-type-taxonomy menu-item-object-category menu-item-847895"><a href="http://citizen.co.za/category/your-life/">Your life</a></li>
<li id="menu-item-847883" class="menu-item menu-item-type-taxonomy menu-item-object-category menu-item-847883"><a href="http://citizen.co.za/category/horses/">Horses</a></li>
<li id="menu-item-847897" class="menu-item menu-item-type-custom menu-item-object-custom menu-item-847897"><a href="http://www.citizen.co.za/multimedia-3/">Multimedia</a></li>
</ul></div>                        </ul>
                    </div>
                </div>

            </div>
        </div>
    </div>
    <!-- Secondary menu starts -->

    <!-- All rights reserved info starts -->
    <div class="all_rights_reserved">
        <div class="container">
            <div class="col-md-12">
                <div class="row">
                    <img src="http://citizen.co.za/wp-content/themes/citizen-v5-2/images/citizen_footer.png?b644a6" alt="The Citizen - Footer" title="The Citizen - Footer" />
                    <p><span class="fa fa-copyright"></span>&nbsp; <span class="year"></span> The Citizen. All rights reserved.</p>
                </div>
            </div>
        </div>
    </div>
    <!-- All rights reserved info ends -->
</div><!--end footer-->
</div><!--wrapper-->
<!-- beginning of wallpaper ads -->
<script type="text/javascript">
                        jQuery(document).ready(function() {

                    jQuery.getJSON('http://ox-d.caxton.co.za/w/1.0/arj?auid=537131831&callback=?', function(jd) {
                        if(jd.ads.ad[0] !== null && jd.ads.ad[0]!== undefined && jd.ads.ad[0]!== 'undefined')
                        {
                            jQuery(".side-ads-wrapper").css({"background-color":"#f0ebee"});
                            jQuery(".side-ads-wrapper").css({"background-image":"url("+ jd.ads.ad[0].creative[0].media+")"});
                            jQuery(".side-ads-wrapper").css({"background-repeat":"no-repeat"});
                            jQuery(".side-ads-wrapper").css({"background-position":"center top"});
                            jQuery(".side-ads-wrapper").wrap("<a href='"+jd.ads.ad[0].creative[0].tracking.click+"' target='_blank'></a>");
                            jQuery(".side-ads-wrapper").after("<div style='position:absolute;left:0px;top:0px;visibility:hidden;'><img src='"+jd.ads.ad[0].creative[0].tracking.impression+"'></div>");
                        }
                    });
                });

                </script>
<!-- end of wallpaper ads -->

<!-- BEGIN EFFECTIVE MEASURE CODE -->
<!-- COPYRIGHT EFFECTIVE MEASURE -->
<script type="text/javascript">
	(function() {
		var em = document.createElement('script'); em.type = 'text/javascript'; em.async = true;
		em.src = ('https:' == document.location.protocol ? 'https://za-ssl' : 'http://za-cdn') + '.effectivemeasure.net/em.js';
		var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(em, s);
	})();
</script>
<noscript>
	<img src="//za.effectivemeasure.net/em_image" alt="" style="position:absolute; left:-5px;" />
</noscript>
<!--END EFFECTIVE MEASURE CODE -->

<link rel='stylesheet' id='gforms_reset_css-css'  href="http://citizen.co.za/wp-content/plugins/gravityforms/css/formreset.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='gforms_formsmain_css-css'  href="http://citizen.co.za/wp-content/plugins/gravityforms/css/formsmain.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='gforms_ready_class_css-css'  href="http://citizen.co.za/wp-content/plugins/gravityforms/css/readyclass.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='gforms_browsers_css-css'  href="http://citizen.co.za/wp-content/plugins/gravityforms/css/browsers.css?b644a6" type='text/css' media='all' />
<link rel='stylesheet' id='gpoll_css-css'  href="http://citizen.co.za/wp-content/plugins/gravityformspolls/css/gpoll.css?b644a6" type='text/css' media='all' />
<script type='text/javascript' src="http://citizen.co.za/wp-content/plugins/caxton-citizen-flexslider-wp-gallery/jquery.flexslider.js?b644a6"></script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/plugins/caxton-citizen-flexslider-wp-gallery/load-slider.js?b644a6"></script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/themes/citizen-v5-2/js/bootstrap.min.js?b644a6"></script>
<script type='text/javascript' src='http://ox-d.caxton.co.za/w/1.0/jstag?ver=20150415'></script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/themes/citizen-v5-2/js/jquery.matchHeight.js?b644a6"></script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/themes/citizen-v5-2/js/site.min.js?b644a6"></script>
<script type='text/javascript'>
/* <![CDATA[ */
var myScript = {"themesUrl":"http:\/\/citizen.co.za\/wp-content\/themes\/citizen-v5-2"};
/* ]]> */
</script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/themes/citizen-v5-2/js/static.min.js?b644a6"></script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/themes/citizen-v5-2/js/scrollspy.min.js?b644a6"></script>
<script type='text/javascript' src='//maps.googleapis.com/maps/api/js?sensor=false&#038;ver=4.3.1'></script>
<script type='text/javascript'>
/* <![CDATA[ */
var ubermenu_data = {"remove_conflicts":"on","reposition_on_load":"off","intent_delay":"300","intent_interval":"100","intent_threshold":"7","scrollto_offset":"50","scrollto_duration":"1000","responsive_breakpoint":"959","accessible":"on","retractor_display_strategy":"responsive","touch_off_close":"on","v":"3.2.1.1","configurations":["main"],"ajax_url":"http:\/\/citizen.co.za\/wp-admin\/admin-ajax.php"};
/* ]]> */
</script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/plugins/ubermenu/assets/js/ubermenu.js?b644a6"></script>
<script type='text/javascript'>
/* <![CDATA[ */
var gpollVars = {"ajaxurl":"http:\/\/citizen.co.za\/wp-admin\/admin-ajax.php","imagesUrl":"http:\/\/citizen.co.za\/wp-content\/plugins\/gravityformspolls\/images"};
var gpoll_strings = {"viewResults":"View results","backToThePoll":"Back to the poll"};
/* ]]> */
</script>
<script type='text/javascript' src="http://citizen.co.za/wp-content/plugins/gravityformspolls/js/gpoll.js?b644a6"></script>
<script  type="text/javascript">
					var disqus_shortname = "thecitizenza";
					if (typeof ds_loaded == "undefined") {
						var ds_loaded = false; //To track loading only once on a page.
					}
					function loadDisqus()
					{
						var disqus_div = document.getElementById("disqus_thread"); //The ID of the Disqus DIV tag
						var top = disqus_div.offsetTop;
						var disqus_data = disqus_div.dataset;
						if ( !ds_loaded && ( window.scrollY || window.pageYOffset ) + window.innerHeight > top ) 
						{
							ds_loaded = true;
							for (var key in disqus_data) 
							{
								if (key.substr(0,6) == "disqus") 
								{
									window["disqus_" + key.replace("disqus","").toLowerCase()] = disqus_data[key];
								}
							}
							var dsq = document.createElement("script");
							dsq.type = "text/javascript";
							dsq.async = true;
							dsq.src = "http://" + window.disqus_shortname + ".disqus.com/embed.js";
							if(document.getElementById("dcl-hidden-div")) {
								document.getElementById("dcl-hidden-div").innerHTML = "Loading...";
							}
							(document.getElementsByTagName("head")[0] || document.getElementsByTagName("body")[0]).appendChild(dsq);
						}    
					}
					var disqus_div_new = document.getElementById("disqus_thread");
					var divExists = disqus_div_new != null;
					if(document.body.scrollHeight < window.innerHeight){
						loadDisqus();
					} else if(divExists) {
						window.onscroll = function() { loadDisqus(); }
					}
					</script><script   type='text/javascript'>
					/* <![CDATA[ */
					var hash = window.location.hash;
					if(hash!==''){
					var ds_loaded = true;
					var dcl_loaded = 1;
					(function() {
						var dsq = document.createElement('script'); dsq.type = 'text/javascript';
						dsq.async = true;
						dsq.src = '//' + disqus_shortname + '.' + 'disqus.com' + '/' + 'embed' + '.js' + '?pname=wordpress&pver=2.84';
						(document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(dsq);
					})();}
					/* ]]> */
					</script><!-- asynchronously loaded ads -->
<script type="text/javascript">
 var OX_12345cxt = OX();
             OX_12345cxt.addAdUnit("536874922");//leaderboard - generic
        OX_12345cxt.setAdUnitSlotId("536874922","leaderboard");
        OX_12345cxt.addAdUnit("536874923");//halfpage - generic
        OX_12345cxt.setAdUnitSlotId("536874923","halfpage-container");
        OX_12345cxt.addAdUnit("536874924");//MPU - generic
        OX_12345cxt.setAdUnitSlotId("536874924","mpu-container");
                    OX_12345cxt.addAdUnit("537079558");//136X130 Top left
        OX_12345cxt.setAdUnitSlotId("537079558","quard-ad-item1");
        OX_12345cxt.addAdUnit("537079559");//136X130 Top right
        OX_12345cxt.setAdUnitSlotId("537079559","quard-ad-item2");
        OX_12345cxt.addAdUnit("537079560");//136X130 Bottom left
        OX_12345cxt.setAdUnitSlotId("537079560","quard-ad-item3");
        OX_12345cxt.addAdUnit("537079561");//136X130 Bottom right
        OX_12345cxt.setAdUnitSlotId("537079561","quard-ad-item4");
        OX_12345cxt.addAdUnit("537084166");//266X185 - most read box
        OX_12345cxt.setAdUnitSlotId("537084166","most-read-ad");
    OX_12345cxt.load();
</script>
<!-- end of asynchronously loaded ads -->

  <script type="text/javascript" src="//s7.addthis.com/js/300/addthis_widget.js#pubid=ra-5474c4b4570894e3" async="async"></script>


<script type="text/javascript">
var addthis_share = addthis_share || {}
addthis_share = {
		title:'',
	passthrough : {
		twitter: {
						via: "TheCitizen_News",
					}
	},
	url_transforms : {
          	shorten: {
               		twitter: 'bitly',
               		facebook: 'bitly',
               		whatsapp:'bitly',
               		email:'bitly',
               		googleplus:'bitly',
               		reddit: 'bitly'
          	}
     	},
     	shorteners : {
          	bitly : {}
     	}
}
</script>


<script type="text/javascript">window.NREUM||(NREUM={});NREUM.info={"beacon":"bam.nr-data.net","licenseKey":"ed2b89cd5d","applicationID":"7426693","transactionName":"NVIHYEVTCBIHAUdQWAwYJFdDWwkPSRFaV1AOUg==","queueTime":0,"applicationTime":711,"atts":"GRUEFg1JGxw=","errorBeacon":"bam.nr-data.net","agent":""}</script></body>
</html>

<!-- Performance optimized by W3 Total Cache. Learn more: http://www.w3-edge.com/wordpress-plugins/

Database Caching using memcached
Object Caching 6076/6196 objects using memcached

 Served from: citizen.co.za @ 2016-02-19 14:37:05 by W3 Total Cache -->
"""

        doc = Document()
        doc.url = 'http://citizen.co.za/153078/outa-claims-proof-e-toll-mismanagement/'
        self.crawler.extract(doc, html)

        self.assertEqual(doc.title, 'Outa claims proof of e-toll mismanagement')
        self.assertEqual(
            doc.summary,
            u'The Opposition to Urban Tolling Alliance (Outa) has once again pleaded with government to listen to \u201ccritics\u201d against e-tolling, in light of new information provided by a whistle blower on the user payment system.',
        )
        self.assertEqual(doc.published_at.strftime('%d %m %Y'), '01 04 2014')
        self.assertEqual(doc.author.name, "Yadhana Jadoo & Alex Mitchley")
        self.assertEqual(doc.medium.name, 'Citizen')

        self.assertEqual(
            doc.text,
            u'The Opposition to Urban Tolling Alliance (Outa) has once again pleaded with government to listen to \u201ccritics\u201d against e-tolling, in light of new information provided by a whistle blower on the user payment system.\n\nThis, as Outa awaits feedback from the Public Protector\u2019s office on a complaint it laid, following \u201cdamning\u201d information it received from a source within the system.\n\nCity Press reported on Sunday that an employee of Austrian Company Kapsch \u2013 used to design the e-toll system \u2013 had warned the SA National Roads Agency Ltd (Sanral) of the high risk in the implementation of a national roll-out.\n\nHe said the e-tolling system was designed to monitor 7 000 km of national roads, with tolls being planned for Durban and Cape Town, it reported.\n\nThe source further stated that there were design flaws within the system and Sanral\u2019s control centre in Midrand had been created to monitor all roads in South Africa.\n\nIf the claims are true, it suggests that Sanral saw the Gauteng highway tolling project as either a starting point for national e-tolling, or it significantly over-invested in a system it did not need.\n\nSanral spokesman Vusi Mona, in rejecting the allegations by the \u201cso-called informant\u201d, said the Public Protector Thuli Madonsela had not yet contacted the entity.\n\nIt would however \u201cco-operate\u201d, should her office conduct an investigation, he added.\n\nMona said Sanral and its concessionaires were in the process of installing the \u201celectronic toll collection equipment\u201d needed at conventional toll plazas across the country.\n\nIt would make the exact details as to which toll plazas and  when this payment method will be available, at an \u201copportune time\u201d.\n\n\u201cElectronic toll collection \u2013 the use of e-tags \u2013 is a method of payment for one\u2019s toll fees. Electronic toll collection does not replace existing toll plazas. It is a tool that toll plazas will use in addition to current methods of payment.\n\n\u201cBy obtaining and e-tag and registering it, e-tolling allows an account holder to use the same e-tag and e-toll account to pay toll fees at any toll plaza equipped to accept e-tags.\u201d\n\nDeputy Public Protector Kevin Malunga, who was handling the complaint, according to Outa, was not immediately available for comment.\n\nOuta chairman Wayne Duvenage told The Citizen that the alliance had always provided an open door for Parliament\u2019s Portfolio Committee on Transport and Government\u2019s Inter-Ministerial Committee (IMC), which previously engaged with stakeholders against e-tolling, prior to its implementation.\n\nIt was important for government to learn from its critics, said Duvenage.\n\n\u201c\u2026 And they are not learning from their critics. We are happy to present to anybody.\u201d\n\nHe described previous IMC engagements as being unfruitful with government unwilling to unpack and explore the rationality of arguments.\n\nThe insider has described \u201cthem as arrogant and dangerous people who steam-roll public opinion \u2026 bully politicians, and business people and do not act in the interests of the country\u201d, according to Outa.\n\nDuvenage hailed the disclosures as a breakthrough which he hoped would start laying the table for \u201cmeaningful multi-lateral engagement with all stakeholders to transcend the mess\u201d.\n\n\u201cThe whistle blower shows the sheer arrogance of the system.\u201d\n\nHe further asked motorists not the \u201cfall\u201d for a system which was not working.\n\n\u201cThe compliance levels are far too low. Don\u2019t be hoodwinked by the propaganda. Now the chickens are coming out to roost.\u201d\n\nJustice Project South Africa (JPSA) chairperson Howard Dembovsky said it was only a matter of time until someone with a \u201cpaining conscious\u201d came forward.\n\n\u201cThis is a very good thing, we need more people to tell the truth behind what has happened and what is happening with the e-tolls,\u201d said Dembovsky.\n\nThe JPSA is convinced that there is corruption behind the controversial system: \u201cIt will come out in the dirty washing, a system rolled out veiled in shrouds of secrecy is a dead giveaway.\u201d\n\nDembovsky echoed Duvenage\u2019s comments, indicating that further IMC engagements would be \u201ca waste of time\u201d.\n\n\u201cThe last round of engagements was just Sanral telling people what was going to happen. Do not waste more time and our money,\u201d he said.\n\n\u201cTake the money and lets have a referendum, this is after all a democracy and we have not held a single referendum on the matter,\u201d said Dembovsky.\n\n\u201cLet\u2019s do it, let\u2019s show what democracy is all about,\u201d he added.\n\n\xa0',
        )
