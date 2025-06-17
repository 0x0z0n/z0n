fetch("data/posts.json")
  .then(response => {
    if (!response.ok) throw new Error("Failed to fetch posts.json");
    return response.json();
  })
  .then(posts => {
    const categories = {};

    posts.forEach(post => {
      const category = (post.category || "Uncategorized").trim();
      if (categories[category]) {
        categories[category]++;
      } else {
        categories[category] = 1;
      }
    });

    const container = document.getElementById("categoryList");
    if (!container) return;

    // Sort categories alphabetically
    const sorted = Object.entries(categories).sort(([a], [b]) => a.localeCompare(b));

    sorted.forEach(([cat, count]) => {
      const card = document.createElement("div");
      card.className = "category-card";
      card.innerHTML = `
        <a href="tags.html#${encodeURIComponent(cat)}">${cat}</a>
        <small>${count} post${count !== 1 ? "s" : ""}</small>
      `;
      container.appendChild(card);
    });
  })
  .catch(err => {
    console.error("Error loading categories:", err);
    const container = document.getElementById("categoryList");
    if (container) {
      container.innerHTML = `<p style="color:#f66;">Unable to load categories.</p>`;
    }
  });
