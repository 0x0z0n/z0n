// ===== Theme Toggle + Selector =====
const toggle = document.querySelector(".theme-toggle");
const icon = toggle.querySelector("i");
const themeSelect = document.getElementById("themeSelect");

// Get saved theme or default
let savedTheme = localStorage.getItem("themeStyle") || "0x0z0n-dark";
document.documentElement.setAttribute("data-theme", savedTheme);

// Set toggle icon and selector value
icon.className = savedTheme.includes("light") ? "fas fa-sun" : "fas fa-moon";
themeSelect.value = savedTheme;

// Function to set theme universally
function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("themeStyle", theme);
  icon.className = theme.includes("light") ? "fas fa-sun" : "fas fa-moon";
  themeSelect.value = theme;
}

// Toggle button click
toggle.addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme");
  let newTheme;
  if(current.includes("dark")) {
    newTheme = current.includes("minimal") ? "minimal-light" : "0x0z0n-light";
  } else {
    newTheme = current.includes("minimal") ? "minimal-dark" : "0x0z0n-dark";
  }
  setTheme(newTheme);
});

// Theme selector change
themeSelect.addEventListener("change", () => {
  setTheme(themeSelect.value);
});

// ===== Search Posts =====
const searchInput = document.getElementById("searchInput");
const postsContainer = document.getElementById("posts");
let allPosts = [];

function renderPosts(posts) {
  postsContainer.innerHTML = "";
  if(posts.length === 0){
    postsContainer.innerHTML = "No posts found.";
    return;
  }

  posts.forEach(post => {
    const article = document.createElement("article");
    article.className = "post-card";
    article.setAttribute("data-tags", post.tags.join(", "));
    const categories = Array.isArray(post.category) ? post.category.join(", ") : post.category;

    // Attack path terminal
    let attackPathText = "";
    if(Array.isArray(post.attack_path) && post.attack_path.length > 0){
      attackPathText = post.attack_path.map(step =>
        `Step ${step.step} | User: ${step.user} | Technique: ${step.technique}\nResult: ${step.result}\nMitigation: ${step.mitigation}\n`
      ).join("\n");
    }

    article.innerHTML = `
      <h2><a href="${post.href}">${post.title}</a></h2>
      <div><strong>Category:</strong><br/>${
        categories ? categories.split(', ').map(cat => {
          const encoded = encodeURIComponent(cat.trim());
          return `<a href="index.html?category=${encoded}" class="category-button">${cat.trim()}</a>`;
        }).join('') : `<span style="color:#888;">Uncategorized</span>`
      }</div>
      <p><strong>Date:</strong> ${post.date}</p>
      <p><strong>Tags:</strong></p>
      <div class="tag-container">
        ${post.tags.map(tag => `<a href="index.html?tag=${encodeURIComponent(tag)}" class="tag-link">${tag}</a>`).join("")}
      </div>
      ${attackPathText ? `<pre class="attack-path-terminal">${attackPathText}</pre>` : ""}
    `;
    postsContainer.appendChild(article);
  });
}

function filterPosts() {
  const query = searchInput.value.trim().toLowerCase();
  const filtered = allPosts.filter(post =>
    post.title.toLowerCase().includes(query) ||
    (Array.isArray(post.category) ? post.category.some(cat => cat.toLowerCase().includes(query)) : (post.category || "").toLowerCase().includes(query)) ||
    post.tags.some(tag => tag.toLowerCase().includes(query)) ||
    (post.date && post.date.startsWith(query))
  );
  renderPosts(filtered);
}

function getParam(name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
}

// Fetch posts
fetch("data/posts.json")
  .then(res => res.json())
  .then(data => {
    allPosts = data;
    const tagParam = getParam("tag");
    const catParam = getParam("category");
    const dateParam = getParam("date");
    let filtered = allPosts;

    if(tagParam){
      searchInput.value = tagParam;
      filtered = allPosts.filter(post => post.tags.some(tag => tag.toLowerCase() === tagParam.toLowerCase()));
    } else if(catParam){
      searchInput.value = catParam;
      filtered = allPosts.filter(post => Array.isArray(post.category) ? post.category.some(cat => cat.toLowerCase() === catParam.toLowerCase()) : (post.category || "").toLowerCase() === catParam.toLowerCase());
    } else if(dateParam){
      searchInput.value = dateParam;
      filtered = allPosts.filter(post => post.date && post.date.startsWith(dateParam));
    }

    renderPosts(filtered);
  });

searchInput.addEventListener("input", filterPosts);

// --- Auto Search via URL Query ---
window.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const query = params.get("search") || params.get("category");
  
  if (query) {
    const searchInput = document.getElementById("searchInput");
    if (searchInput) {
      searchInput.value = query;

      // Trigger input event to reuse your existing filtering logic
      const event = new Event("input");
      searchInput.dispatchEvent(event);
    }
  }
});
