/* Triagle: the few behaviours shared by every page. Kept in a file, not in the
   page, so the page policy can refuse every script that is not ours. */
(function () {
  document.addEventListener('click', function (e) {
    var el = e.target.closest ? e.target.closest('[data-act]') : null;
    if (!el) return;
    var act = el.getAttribute('data-act');
    if (act === 'print') window.print();
    else if (act === 'reload') location.reload();
  });
  document.addEventListener('change', function (e) {
    var el = e.target.closest ? e.target.closest('select[data-act="submit"]') : null;
    if (el && el.form) el.form.submit();
  });
})();
