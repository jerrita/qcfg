document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-token]");
  if (!button || button.disabled) return;

  button.disabled = true;
  try {
    const response = await fetch(button.dataset.copyToken, { redirect: "error" });
    if (!response.ok) throw new Error("Token request failed");
    await navigator.clipboard.writeText(await response.text());
    button.textContent = "copied";
  } catch {
    button.textContent = "copy failed";
  } finally {
    button.disabled = false;
  }
});
