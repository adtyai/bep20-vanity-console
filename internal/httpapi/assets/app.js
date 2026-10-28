document.addEventListener("click", function (ev) {
  var btn = ev.target.closest("[data-copy]");
  if (!btn) return;
  var el = document.getElementById(btn.getAttribute("data-copy"));
  if (!el) return;
  var text = el.value;
  var done = function () { btn.textContent = "已复制"; };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(function () {
      el.focus();
      el.select();
    });
    return;
  }
  el.focus();
  el.select();
});
