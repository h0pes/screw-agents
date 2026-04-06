// Fixture: js-dom-innerhtml — DOM-based XSS via location.hash and innerHTML
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: Client-side source (location.hash, location.search) flows to DOM sink (innerHTML, document.write)

// DOM-based XSS: the vulnerability exists entirely in client-side JavaScript.
// The server never sees the payload (fragment identifiers are not sent to the server).

// VULNERABLE: location.hash parsed and injected via innerHTML
// Attacker sends: https://example.com/page#<img src=x onerror=alert(document.cookie)>
function renderTabContent(): void {
  const hash = window.location.hash.substring(1);
  const tabContent = document.getElementById("tab-content");

  if (tabContent) {
    // VULNERABLE: hash fragment inserted as raw HTML
    // location.hash is a client-side-only source — no server-side encoding can protect this
    tabContent.innerHTML = `<div class="tab-panel"><h2>${decodeURIComponent(hash)}</h2></div>`;
  }
}

window.addEventListener("hashchange", renderTabContent);

// VULNERABLE: location.search parsed and written via innerHTML
// Attacker sends: ?message=<svg/onload=alert(1)>
function displayNotification(): void {
  const params = new URLSearchParams(window.location.search);
  const message = params.get("message");

  if (message) {
    const banner = document.getElementById("notification-banner");
    if (banner) {
      // VULNERABLE: URL parameter injected into innerHTML
      banner.innerHTML = `<div class="alert alert-info">${message}</div>`;
    }
  }
}

// VULNERABLE: document.write() with user-controlled input from referrer
// Referrer can be manipulated if attacker controls the linking page
function logReferrer(): void {
  const referrer = document.referrer;
  if (referrer) {
    // VULNERABLE: document.write() is a DOM XSS sink
    // If referrer contains HTML/script content, it executes in page context
    document.write(
      `<div class="referrer-info">You came from: <a href="${referrer}">${referrer}</a></div>`
    );
  }
}

document.addEventListener("DOMContentLoaded", () => {
  renderTabContent();
  displayNotification();
  logReferrer();
});
