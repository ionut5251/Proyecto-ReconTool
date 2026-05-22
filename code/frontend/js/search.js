const form = document.getElementById("search-form");
const input = document.getElementById("target-input");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const target = input.value.trim();
  if (!target) return;

  const url = new URL("/results.html", window.location.origin);
  url.searchParams.set("target", target);
  window.location.href = url.toString();
});
