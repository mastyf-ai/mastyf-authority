// Experimentation tag, live version (benign fixture).
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
})();
