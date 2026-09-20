"""A small, locally generated landscape for trying the complete workflow."""

import io
import random

from PIL import Image, ImageDraw, ImageFilter


def demo_photo() -> bytes:
    width, height = 1200, 800
    image = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(image)
    for y in range(height):
        t = y / height
        draw.line((0, y, width, y), fill=(int(222 - t * 53), int(208 - t * 30), int(183 - t * 34)))
    draw.ellipse((780, 130, 898, 248), fill=(248, 230, 184))
    draw.polygon(
        [
            (0, 455),
            (160, 360),
            (300, 427),
            (510, 238),
            (730, 439),
            (936, 287),
            (1200, 429),
            (1200, 800),
            (0, 800),
        ],
        fill=(131, 145, 137),
    )
    draw.polygon(
        [(414, 334), (510, 238), (602, 329), (547, 310), (512, 283), (479, 325), (466, 305)],
        fill=(222, 218, 196),
    )
    draw.polygon(
        [
            (0, 560),
            (194, 430),
            (341, 504),
            (487, 436),
            (706, 588),
            (947, 435),
            (1200, 517),
            (1200, 800),
            (0, 800),
        ],
        fill=(78, 110, 104),
    )
    draw.polygon(
        [(0, 672), (260, 598), (518, 672), (837, 546), (1200, 657), (1200, 800), (0, 800)],
        fill=(40, 73, 68),
    )
    rng = random.Random(7)
    for _ in range(180):
        x, y = rng.randrange(width), rng.randrange(685, 840)
        h = rng.randrange(20, 100)
        draw.polygon([(x, y - h), (x - h // 5, y), (x + h // 5, y)], fill=(29, 57, 51))
    image = image.filter(ImageFilter.GaussianBlur(0.45))
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()
