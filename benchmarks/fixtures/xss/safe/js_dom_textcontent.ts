// Fixture: js-dom-textcontent — element.textContent = userInput (safe DOM API)
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: textContent, createTextNode, and insertAdjacentText are safe DOM write APIs

// SAFE: textContent does not parse HTML — it treats the value as plain text
// Unlike innerHTML, assigning to textContent never creates DOM elements from the string
function renderTabContent(): void {
  const hash = window.location.hash.substring(1);
  const tabContent = document.getElementById("tab-content");

  if (tabContent) {
    // SAFE: textContent treats the value as literal text, not HTML
    // Input "<script>alert(1)</script>" displays as the literal string
    tabContent.textContent = decodeURIComponent(hash);
  }
}

window.addEventListener("hashchange", renderTabContent);

// SAFE: createTextNode produces a text node that cannot contain HTML elements
function displayNotification(): void {
  const params = new URLSearchParams(window.location.search);
  const message = params.get("message");

  if (message) {
    const banner = document.getElementById("notification-banner");
    if (banner) {
      // SAFE: createTextNode creates a pure text node — no HTML parsing
      const textNode = document.createTextNode(message);
      const wrapper = document.createElement("div");
      wrapper.className = "alert alert-info";
      wrapper.appendChild(textNode);

      banner.innerHTML = ""; // Clear existing content
      banner.appendChild(wrapper);
    }
  }
}

// SAFE: insertAdjacentText inserts text content, not HTML
function addStatusMessage(message: string): void {
  const statusBar = document.getElementById("status-bar");
  if (statusBar) {
    // SAFE: "Text" variants (insertAdjacentText vs insertAdjacentHTML) don't parse HTML
    statusBar.insertAdjacentText("beforeend", message);
  }
}

// SAFE: setAttribute for non-event-handler attributes is safe
function updateSearchField(): void {
  const params = new URLSearchParams(window.location.search);
  const query = params.get("q") || "";

  const searchInput = document.getElementById("search-input") as HTMLInputElement;
  if (searchInput) {
    // SAFE: setting .value on an input element does not parse HTML
    searchInput.value = query;
    // SAFE: setAttribute on non-event attributes is safe (value is HTML-encoded by the browser)
    searchInput.setAttribute("placeholder", `Search for: ${query}`);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  renderTabContent();
  displayNotification();
  updateSearchField();
});
