import os
import re

dream_src = r"c:\Netfusion\Dream\src"

urls_called = set()

pattern = re.compile(r' fetch\s*\(\s*[`"\']([^`"\']+)[`"\']|fetch\s*\(\s*([a-zA-Z0-9_\.\$\{\}]+)')

for root, dirs, files in os.walk(dream_src):
    for f in files:
        if f.endswith(('.ts', '.tsx', '.js', '.jsx')):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                # find all fetch or axios or API_URL references
                matches = re.findall(r'fetch\s*\(\s*([`\'"][^`\'"]+[`\'"]|\w+\([^)]*\)|\w+)', content)
                for m in matches:
                    urls_called.add(m)

print(f"Found {len(urls_called)} unique fetch call expressions in frontend:")
for u in sorted(urls_called):
    print("  ", u)
