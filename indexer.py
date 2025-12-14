import os
import json
import time

# Configuration
ROOT_DIR = "."
OUTPUT_FILE = "data/search_index.json"
# Folders to skip
EXCLUDE_DIRS = {'.git', '.github', 'assets', 'data', '__pycache__'}
# Files to skip
EXCLUDE_FILES = {'index.html', 'indexer.py', 'style.css', 'search_index.json'}
# Extensions to include
VALID_EXTS = {'.html', '.pdf', '.txt', '.md', '.py', '.sh', '.js'}

def get_file_info(filepath):
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    
    # Generate a pretty title from filename
    title = os.path.splitext(filename)[0].replace('-', ' ').replace('_', ' ').title()
    
    # Categorize based on extension
    category = "File"
    icon = "fa-file"
    if ext == ".html": category = "Page"; icon = "fa-globe"
    elif ext == ".pdf": category = "Doc"; icon = "fa-file-pdf"
    elif ext in [".py", ".sh", ".js"]: category = "Script"; icon = "fa-code"
    elif ext in [".md", ".txt"]: category = "Note"; icon = "fa-sticky-note"

    return {
        "title": title,
        "path": filepath,
        "type": category,
        "icon": icon,
        "ext": ext,
        "date": time.strftime('%Y-%m-%d', time.gmtime(os.path.getmtime(filepath)))
    }

data = []

print(f"[*] Scanning {os.path.abspath(ROOT_DIR)}...")

for root, dirs, files in os.walk(ROOT_DIR):
    # Remove excluded directories from traversal
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    
    for file in files:
        if file in EXCLUDE_FILES: continue
        
        ext = os.path.splitext(file)[1].lower()
        if ext in VALID_EXTS:
            # Create relative path
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, ROOT_DIR)
            
            # Add to index
            entry = get_file_info(rel_path)
            data.append(entry)
            print(f"  + Indexed: {rel_path}")

# Ensure data directory exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

with open(OUTPUT_FILE, 'w') as f:
    json.dump(data, f, indent=2)

print(f"\n[+] Success! {len(data)} items indexed to {OUTPUT_FILE}")
