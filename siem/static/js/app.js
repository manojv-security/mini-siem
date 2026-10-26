/* Small shared behaviours (kept out of templates so the CSP can forbid inline scripts). */
(function () {
  "use strict";

  // <form data-confirm="Are you sure?"> asks before submitting.
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  // <select data-autosubmit> submits its form on change.
  document.querySelectorAll("select[data-autosubmit]").forEach((select) => {
    select.addEventListener("change", () => select.form.submit());
  });

  // Disable submit buttons while a form posts, to avoid double uploads.
  document.querySelectorAll("form[data-busy]").forEach((form) => {
    form.addEventListener("submit", () => {
      form.querySelectorAll("button[type=submit]").forEach((button) => {
        button.disabled = true;
        button.dataset.label = button.textContent;
        button.textContent = form.dataset.busy;
      });
    });
  });

  // Rules page: "Save and re-run" sets a hidden field.
  document.querySelectorAll("[data-rerun]").forEach((button) => {
    button.addEventListener("click", () => {
      const field = document.getElementById("rerun-field");
      if (field) field.value = "1";
    });
  });
})();
