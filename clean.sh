#!/bin/bash
# cleanup_large_files.sh
# Removes large files from git history and force pushes, without touching .gitignore

# -------------------------------
# ✅ Step 0: Ensure git-filter-repo is installed
# pip install git-filter-repo
# -------------------------------

# 1️⃣ List of large files to remove
FILES=(
"R3S/HTB/AI/GTSRB.zip"
"R3S/PEN-300 OSEP .html"
"R3S/WEB-200 OSWA.html"
)

# 2️⃣ Untrack files from current commit
for f in "${FILES[@]}"; do
    if git ls-files --error-unmatch "$f" > /dev/null 2>&1; then
        echo "Removing $f from index..."
        git rm --cached "$f"
    fi
done

# 3️⃣ Commit the removal
git commit -m "Remove large files from tracking"

# 4️⃣ Purge large files from Git history using git-filter-repo
# Use --force because this is not a fresh clone
for f in "${FILES[@]}"; do
    echo "Purging $f from history..."
    git filter-repo --force --path "$f" --invert-paths
done

# 5️⃣ Force push the cleaned repo
echo "Force pushing cleaned repo..."
git push origin main --force

echo "✅ Large files removed and repo pushed successfully."
