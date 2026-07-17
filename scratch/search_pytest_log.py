with open("C:/Users/ujjwa/.gemini/antigravity-ide/brain/c53035d0-a196-4ba6-b015-5612d904926f/.system_generated/tasks/task-99.log", "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")
# Find where FAILURES or traceback starts
for idx, line in enumerate(lines):
    if "FAILURES" in line:
        print(f"Found FAILURES at line {idx+1}")
        for l in lines[idx:idx+100]:
            print(l, end="")
        break
