from __future__ import annotations


class BadgeGenerator:
    """Generates dynamic GitHub Shields-compliant SVG badges for project READMEs."""

    @staticmethod
    def generate_svg(score: int, status: str = "READY TO SHIP") -> str:
        score_val = max(0, min(100, score))
        status_upper = status.upper()

        if status_upper == "READY TO SHIP" or (score_val >= 80 and "BLOCK" not in status_upper):
            color = "#10b981"  # Emerald Green
            label_text = f"{score_val}% passing"
        elif "NEED" in status_upper or (score_val >= 50 and "BLOCK" not in status_upper):
            color = "#f59e0b"  # Amber
            label_text = f"{score_val}% review"
        else:
            color = "#ef4444"  # Red
            label_text = f"{score_val}% blocked"

        # Width calculations
        left_text = "secureship"
        left_width = 75
        right_width = 85
        total_width = left_width + right_width

        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{left_text}: {label_text}">
  <title>{left_text}: {label_text}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_width}" height="20" fill="#1e293b"/>
    <rect x="{left_width}" width="{right_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{left_width * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{left_width * 8}">{left_text}</text>
    <text x="{left_width * 5}" y="140" transform="scale(.1)" fill="#fff" textLength="{left_width * 8}">{left_text}</text>
    <text aria-hidden="true" x="{(left_width + right_width / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{right_width * 8}">{label_text}</text>
    <text x="{(left_width + right_width / 2) * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="{right_width * 8}">{label_text}</text>
  </g>
</svg>"""
        return svg
