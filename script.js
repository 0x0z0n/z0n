
const tagCounts = {};
const posts = document.querySelectorAll(".post-card");
const tagListEl = document.getElementById("tagList");

posts.forEach(card => {
  const tags = card.getAttribute("data-tags")?.split(",").map(tag => tag.trim()) || [];
  tags.forEach(tag => {
    tagCounts[tag] = (tagCounts[tag] || 0) + 1;
  });
});

function renderTags() {
  if (!tagListEl) return;
  tagListEl.innerHTML = "";
  Object.entries(tagCounts).forEach(([tag, count]) => {
    const tagEl = document.createElement("a");
    tagEl.className = "tag";
    tagEl.href = "index.html#" + tag;
    tagEl.textContent = `${tag} (${count})`;
    tagListEl.appendChild(tagEl);
  });
}

function filterTags() {
  const val = document.getElementById("searchTagInput").value.toLowerCase();
  document.querySelectorAll(".tag").forEach(tag => {
    tag.style.display = tag.textContent.toLowerCase().includes(val) ? "inline-block" : "none";
  });
}

function filterPosts() {
  const val = document.getElementById("searchInput").value.toLowerCase();
  posts.forEach(post => {
    post.style.display = post.textContent.toLowerCase().includes(val) ? "block" : "none";
  });
}

document.getElementById("themeToggle")?.addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme");
  document.documentElement.setAttribute("data-theme", current === "dark" ? "light" : "dark");
});

renderTags();
