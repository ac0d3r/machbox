<template>
  <div class="app">
    <header class="top-header">
      <div class="brand">
        <svg class="logo" width="28" height="28" viewBox="0 0 48 48" fill="none"><rect width="48" height="48" rx="10" fill="url(#orangeGradient)"/><path d="M14 34V18l6 8 6-8v16" stroke="white" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/><rect x="14" y="14" width="20" height="20" rx="3" stroke="white" stroke-width="2.5" fill="none" opacity="0.35"/><defs><linearGradient id="orangeGradient" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse"><stop stop-color="#FF8C42"/><stop offset="1" stop-color="#E85D04"/></linearGradient></defs></svg>
        <span class="title">Machbox</span>
      </div>
      <span class="subtitle">macOS Malware Analysis Sandbox</span>
    </header>
    <div class="main-wrap">
      <router-view />
    </div>
  </div>
</template>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body, #app, .app { height: 100%; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: #f5f7fa;
  color: #333;
  font-size: 14px;
}
.app { display: flex; flex-direction: column; }
.top-header {
  background: #1a1a2e;
  color: #fff;
  padding: 0 24px;
  height: 52px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}
.brand { display: flex; align-items: center; gap: 10px; }
.logo {
  width: 28px; height: 28px;
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
}
.title { font-size: 18px; font-weight: 600; }
.subtitle { font-size: 13px; opacity: 0.7; }
.main-wrap { flex: 1; overflow: auto; }
</style>
