
fetch("data/posts.json")
  .then(res => res.json())
  .then(data => {
    const categories = {};
    data.forEach(post => {
      const cat = post.category || "Uncategorized";
      categories[cat] = categories[cat] ? categories[cat] + 1 : 1;
    });

    const container = document.getElementById("categoryList");
    if (container) {
      Object.entries(categories).forEach(([cat, count]) => {
        const card = document.createElement("div");
        card.className = "category-card";
        card.innerHTML = `
          <a href="tags.html#${encodeURIComponent(cat)}">${cat}</a>
          <span>${count} post${count > 1 ? "s" : ""}</span>
        `;
        container.appendChild(card);
      });
    }
  });
