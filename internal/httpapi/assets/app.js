function fieldDirty(el) {
  if (!el || el.type === "hidden" || el.type === "submit" || el.type === "button") return false;
  if (el.type === "checkbox" || el.type === "radio") return el.checked !== el.defaultChecked;
  return el.value !== el.defaultValue;
}

function formDirty() {
  var fields = document.querySelectorAll("input, textarea, select");
  for (var i = 0; i < fields.length; i++) {
    if (fieldDirty(fields[i])) return true;
  }
  return false;
}

function editing() {
  var active = document.activeElement;
  if (!active) return false;
  var tag = active.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

var live = document.querySelector('meta[name="live-refresh"]');
if (live) {
  var seconds = parseInt(live.getAttribute("content"), 10);
  if (seconds > 0) {
    window.setInterval(function () {
      if (formDirty() || editing()) return;
      window.location.reload();
    }, seconds * 1000);
  }
}

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
