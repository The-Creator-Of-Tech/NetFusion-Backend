import os
import ast
import sys

project_root = r"c:\Netfusion\NetFusion-Agent"

routers_found = []

for root, dirs, files in os.walk(project_root):
    dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', '.pytest_cache', 'venv', '.venv', 'node_modules', 'brain']]
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            relpath = os.path.relpath(filepath, project_root)
            if relpath.startswith('scratch'):
                continue
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                if 'APIRouter' in content:
                    tree = ast.parse(content, filename=filepath)
                    for node in ast.walk(tree):
                        target_name = None
                        val = None
                        if isinstance(node, ast.Assign):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    target_name = target.id
                                    val = node.value
                        elif isinstance(node, ast.AnnAssign):
                            if isinstance(node.target, ast.Name):
                                target_name = node.target.id
                                val = node.value

                        if target_name and val and isinstance(val, ast.Call):
                            func = val.func
                            func_name = ""
                            if isinstance(func, ast.Name):
                                func_name = func.id
                            elif isinstance(func, ast.Attribute):
                                func_name = func.attr
                            if func_name == 'APIRouter':
                                prefix = None
                                tags = []
                                for kw in val.keywords:
                                    if kw.arg == 'prefix':
                                        if isinstance(kw.value, ast.Constant):
                                            prefix = kw.value.value
                                    elif kw.arg == 'tags':
                                        if isinstance(kw.value, ast.List):
                                            tags = [elt.value for elt in kw.value.elts if isinstance(elt, ast.Constant)]
                                routers_found.append({
                                    'file': relpath,
                                    'var_name': target_name,
                                    'prefix': prefix,
                                    'tags': tags,
                                    'line': node.lineno
                                })
            except Exception as e:
                print(f"Error parsing {relpath}: {e}")

print(f"Found {len(routers_found)} APIRouter instances:")
for r in sorted(routers_found, key=lambda x: x['file']):
    print(f"File: {r['file']} (line {r['line']}) | Var: {r['var_name']} | Prefix: {r['prefix']} | Tags: {r['tags']}")
