import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

// Register the service worker so the console is installable and opens offline. It only
// caches the same-origin shell and immutable assets; live /api traffic is never cached.
// A secure context (HTTPS or localhost) is required, so it is a no-op over plain-HTTP LAN.
if ('serviceWorker' in navigator && window.isSecureContext) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
      // Registration is a progressive enhancement; the console works without it.
    });
  });
}
