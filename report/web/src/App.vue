<template>
  <div class="app">
    <header class="top-header">
      <div class="brand">
        <img class="logo" src="/favicon.svg" width="28" height="28" alt="Machbox" />
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
