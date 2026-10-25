try {
  localStorage.removeItem("htmx-history-cache");
} catch {}

window.addEventListener("pageshow", (event) => {
  if (event.persisted) window.location.reload();
});
