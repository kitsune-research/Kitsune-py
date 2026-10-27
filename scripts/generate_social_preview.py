"""
Kitsune NIDS: Social Preview Generator (1280x640 px)
Generates high-contrast OpenGraph card for GitHub & LinkedIn.
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

# 1. Canvas setup (Exact GitHub OpenGraph dimensions)
WIDTH, HEIGHT = 1280, 640
BG_COLOR = (13, 17, 23)        # GitHub Dark Dimmed #0d1117
CARD_BG = (22, 27, 34)         # GitHub Card Dark #161b22
ACCENT_ORANGE = (255, 123, 37) # Kitsune Orange #ff7b25
ACCENT_CYAN = (56, 189, 248)   # Telemetry Cyan #38bdf8
TEXT_WHITE = (240, 246, 252)   # Pure White
TEXT_MUTED = (139, 148, 158)   # Secondary Gray
BORDER_COLOR = (48, 54, 61)    # Outline Gray

image = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
draw = ImageDraw.Draw(image)

# 2. Outer decorative tech border
draw.rectangle([(20, 20), (WIDTH - 20, HEIGHT - 20)], outline=BORDER_COLOR, width=2)
draw.line([(20, 20), (80, 20)], fill=ACCENT_ORANGE, width=4)
draw.line([(20, 20), (20, 80)], fill=ACCENT_ORANGE, width=4)
draw.line([(WIDTH - 80, HEIGHT - 20), (WIDTH - 20, HEIGHT - 20)], fill=ACCENT_CYAN, width=4)
draw.line([(WIDTH - 20, HEIGHT - 80), (WIDTH - 20, HEIGHT - 20)], fill=ACCENT_CYAN, width=4)

# 3. Typography setup (fallbacks to default if TrueType fonts not locally indexed)
try:
    font_brand = ImageFont.truetype("consola.ttf", 68)
    font_title = ImageFont.truetype("consola.ttf", 32)
    font_sub = ImageFont.truetype("consolab.ttf", 22)
    font_badge = ImageFont.truetype("consolab.ttf", 20)
except Exception:
    font_brand = font_title = font_sub = font_badge = ImageFont.load_default()

# 4. Header: Brand + Version Badge
draw.text((70, 75), "Kitsune-py", font=font_brand, fill=TEXT_WHITE)

# Draw release badge
draw.rounded_rectangle([(440, 90), (545, 130)], radius=6, fill=ACCENT_ORANGE)
draw.text((455, 98), "v0.3.1", font=font_badge, fill=(0, 0, 0))

# 5. Core Title & Subtitle
draw.text((70, 185), "Unsupervised Online Network Anomaly Detection", font=font_title, fill=ACCENT_CYAN)
draw.text((70, 235), "NDSS 2018 Reference Architecture | Y. Mirsky et al.", font=font_sub, fill=TEXT_MUTED)

# 6. Architecture highlights (Metric Badges)
metrics = [
    ("FEATURE EXTRACTION", "AfterImage O(1) Stream", ACCENT_CYAN),
    ("FEATURE MAPPING", "corClust (m <= 10 Bound)", ACCENT_ORANGE),
    ("ANOMALY ENSEMBLE", "KitNET O(k^2) Multi-AE", ACCENT_CYAN),
    ("BASELINE TRAINING", "Online 1-Pass SGD", ACCENT_ORANGE),
]

card_y = 310
card_w = 265
card_h = 135
card_spacing = 290

for idx, (label, val, accent) in enumerate(metrics):
    cx = 70 + (idx * card_spacing)
    # Box background
    draw.rounded_rectangle([(cx, card_y), (cx + card_w, card_y + card_h)], radius=8, fill=CARD_BG, outline=BORDER_COLOR, width=1)
    # Accent top stripe
    draw.line([(cx + 10, card_y), (cx + card_w - 10, card_y)], fill=accent, width=3)
    # Label & text
    draw.text((cx + 16, card_y + 25), label, font=font_badge, fill=TEXT_MUTED)
    draw.text((cx + 16, card_y + 65), val, font=font_sub, fill=TEXT_WHITE)

# 7. Mathematical Invariants Footer
footer_text = "Vector: x in R^100  |  Damped Windows: lambda in {5, 3, 1, 0.1, 0.01}  |  Threshold: Log-Normal tau"
draw.text((70, 560), footer_text, font=font_sub, fill=ACCENT_CYAN)

# 8. Export artifact
out_dir = Path("docs/assets")
out_dir.mkdir(parents=True, exist_ok=True)
out_file = out_dir / "social_preview.png"
image.save(out_file, "PNG", optimize=True)
print(f"[+] Social preview banner compiled successfully: {out_file.resolve()}")