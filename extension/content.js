// Lightweight page-side context only. No page content or credentials are collected.
(() => {
  if (window.top !== window) return;
  document.documentElement.dataset.dnsSentinelAvailable = "true";
})();