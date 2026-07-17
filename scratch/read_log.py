with open("output.log", "r", encoding="utf-16-le", errors="ignore") as f:
    content = f.read()

lines = content.splitlines()
print(f"Total lines in output.log: {len(lines)}")

# Search for PacketCaptureExecutor, exception, or traceback
for i, line in enumerate(lines):
        safe_line = line.encode('ascii', errors='replace').decode('ascii')
        print(f"Line {i+1}: {safe_line}")
