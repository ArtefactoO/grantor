"""Build a compact GIF from recorded PNG states; requires Pillow."""
import sys
import json
from pathlib import Path
from PIL import Image

source, destination = map(Path, sys.argv[1:3])
manifest = source / "capture.json"
paths = [source / f"{i:02d}.png" for i in range(json.loads(manifest.read_text())["frames"])] if manifest.exists() else sorted(source.glob("[0-9][0-9].png"))
if not paths:
    raise SystemExit("No recorded frames")
frames = []
for path in paths:
    frame = Image.open(path).convert("RGB")
    frame.thumbnail((1100, 800), Image.Resampling.LANCZOS)
    frames.append(frame)
sheet = Image.new("RGB", (frames[0].width, sum(frame.height for frame in frames)))
y = 0
for frame in frames:
    sheet.paste(frame, (0, y))
    y += frame.height
palette = sheet.quantize(colors=256)
frames = [frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame in frames]
destination.parent.mkdir(parents=True, exist_ok=True)
frames[0].save(destination, save_all=True, append_images=frames[1:], duration=[1800]*len(frames), loop=0, optimize=True, disposal=2)
print(destination.name, destination.stat().st_size)
