// assets/js/app.js

// Highlight the active navigation link
document.addEventListener("DOMContentLoaded", function() {
  const navLinks = document.querySelectorAll(".nav-link");
  navLinks.forEach(link => {
    link.addEventListener("click", function() {
      navLinks.forEach(link => link.classList.remove("active"));
      this.classList.add("active");
    });
  });
});

// Open and close mobile navigation accessibly
document.addEventListener("DOMContentLoaded", function() {
  const mobileToggle = document.getElementById("mobile-toggle");
  const mobileMenu = document.getElementById("mobile-menu");

  mobileToggle.addEventListener("click", function() {
    mobileMenu.classList.toggle("show");
    mobileToggle.setAttribute("aria-expanded", mobileMenu.classList.contains("show"));
  });
});

// Show consistent loading, success, and error messages
function showMessage(container, message, type) {
  const messageElement = document.createElement("div");
  messageElement.className = `message ${type}`;
  messageElement.textContent = message;
  container.innerHTML = ""; // Clear existing messages
  container.appendChild(messageElement);
}

// Reusable API request helpers using the Fetch API
async function fetchRequest(url, method = "GET", body = null) {
  try {
    const response = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json"
      },
      body: body ? JSON.stringify(body) : null
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Fetch error:", error);
    showMessage(document.getElementById("message-container"), "Error: Please try again later.", "error");
    throw error;
  }
}

// Parse JSON responses safely
function safeParseJson(json) {
  try {
    return JSON.parse(json);
  } catch (e) {
    console.error("Error parsing JSON:", e);
    throw e;
  }
}

// Prevent duplicate form submissions
function preventDuplicateSubmission(formId) {
  const form = document.getElementById(formId);
  form.addEventListener("submit", function() {
    const submitButton = form.querySelector("button[type='submit']");
    if (submitButton.dataset.submitted) {
      return false;
    }
    submitButton.dataset.submitted = "true";
    submitButton.disabled = true;
  });
}

// Format timestamps and risk-level labels safely
function formatTimestamp(timestamp) {
  const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
  return new Date(timestamp).toLocaleTimeString('en-US', options);
}

function formatRiskLevel(risk) {
  switch (risk.toUpperCase()) {
    case 'LOW':
      return '<span class="risk low">Low</span>';
    case 'MEDIUM':
      return '<span class="risk medium">Medium</span>';
    case 'HIGH':
      return '<span class="risk high">High</span>';
    default:
      return '<span class="risk unknown">Unknown</span>';
  }
}

// How each HTML page should load this shared file
// Add the following script tag to the head or end of the body of each HTML page
// <script src="assets/js/app.js"></script>