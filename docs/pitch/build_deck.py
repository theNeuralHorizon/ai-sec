#!/usr/bin/env python3
"""Fill the Canva startup template with the live Aegis story and screenshots."""

from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont
from pptx import Presentation
from pptx.enum.shapes import MSO_SHAPE_TYPE

ROOT = Path("/workspace")
TEMPLATE = Path(
    "/home/ubuntu/.cursor/projects/workspace/uploads/"
    "White_Blue_and_Grey_Modern_Startup_Pitch_Deck_Presentation-2_1605.pptx"
)
SHOTS = ROOT / "docs/pitch/screenshots"
ASSETS = ROOT / "docs/pitch/assets"
OUT = ROOT / "docs/pitch/Aegis_Judge_Pitch_Deck.pptx"

NAVY = (15, 18, 24)
INK = (66, 66, 66)
BLUE = (90, 142, 232)
BLUE_DEEP = (46, 92, 184)
SLATE = (176, 190, 206)
WHITE = (255, 255, 255)
MINT = (82, 189, 146)
CRIT = (232, 104, 109)


def font(size: int, bold: bool = True) -> ImageFont.FreeTypeFont:
    path = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    return ImageFont.truetype(path, size)


def rounded(im: Image.Image, radius: int) -> Image.Image:
    im = im.convert("RGBA")
    mask = Image.new("L", im.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, im.width, im.height), radius=radius, fill=255)
    im.putalpha(mask)
    return im


def contain(im: Image.Image, size: tuple[int, int], bg: tuple[int, int, int] = (18, 22, 30)) -> Image.Image:
    tw, th = size
    canvas = Image.new("RGB", size, bg)
    scale = min(tw / im.width, th / im.height)
    nw, nh = max(1, int(im.width * scale)), max(1, int(im.height * scale))
    resized = im.convert("RGB").resize((nw, nh), Image.Resampling.LANCZOS)
    canvas.paste(resized, ((tw - nw) // 2, (th - nh) // 2))
    return canvas


def framed_shot(src: Path, size: tuple[int, int], focus: str = "flow") -> Image.Image:
    w, h = size
    inner = contain(Image.open(src), (w - 36, h - 36))
    inner = rounded(inner, 28)
    canvas = Image.new("RGBA", (w, h), (15, 18, 24, 255))
    shadow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sd.rounded_rectangle((16, 22, w - 8, h - 6), radius=32, fill=(0, 0, 0, 90))
    shadow = shadow.filter(ImageFilter.GaussianBlur(8))
    canvas.alpha_composite(shadow)
    canvas.alpha_composite(inner, (18, 14))
    return canvas.convert("RGB")


def two_up(top: Path, bottom: Path, size: tuple[int, int]) -> Image.Image:
    w, h = size
    canvas = Image.new("RGB", (w, h), (15, 18, 24))
    gap = 18
    pane_h = (h - 36 - gap) // 2
    a = rounded(contain(Image.open(top), (w - 36, pane_h)), 22)
    b = rounded(contain(Image.open(bottom), (w - 36, pane_h)), 22)
    canvas = canvas.convert("RGBA")
    canvas.alpha_composite(a, (18, 16))
    canvas.alpha_composite(b, (18, 16 + pane_h + gap))
    return canvas.convert("RGB")


def team_card(initial: str, role: str, size: tuple[int, int], hue: tuple[int, int, int], fill_rect: tuple[float, float, float, float] | None = None) -> Image.Image:
    """Letter sits in the visible oval crop (Canva fillRect), not the geometric image center."""
    w, h = size
    im = Image.new("RGB", (w, h), hue)
    draw = ImageDraw.Draw(im)
    if fill_rect is None:
        cx, cy = w / 2, h / 2
        vis_w, vis_h = w, h
    else:
        left, top, right, bottom = fill_rect
        img_x0, img_x1 = left, 100.0 - right
        img_y0, img_y1 = top, 100.0 - bottom
        span_x = img_x1 - img_x0
        span_y = img_y1 - img_y0
        vis_l = (0.0 - img_x0) / span_x
        vis_r = (100.0 - img_x0) / span_x
        vis_t = (0.0 - img_y0) / span_y
        vis_b = (100.0 - img_y0) / span_y
        cx = ((vis_l + vis_r) / 2) * w
        cy = ((vis_t + vis_b) / 2) * h
        vis_w = (vis_r - vis_l) * w
        vis_h = (vis_b - vis_t) * h
    f = font(max(48, int(min(vis_w, vis_h) * 0.52)))
    bbox = draw.textbbox((0, 0), initial, font=f)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    # textbbox origin is not (0,0); offset by bbox min
    draw.text((cx - tw / 2 - bbox[0], cy - th / 2 - bbox[1]), initial, font=f, fill=WHITE)
    return im


def pie_chart(size: tuple[int, int]) -> Image.Image:
    w, h = size
    im = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(im)
    slices = [
        (0.35, (46, 92, 184), "Gateway"),
        (0.25, (90, 142, 232), "Eval"),
        (0.22, (152, 176, 204), "Adapters"),
        (0.18, (66, 66, 66), "UX"),
    ]
    pad = 70
    box = (pad, pad, w - pad, h - pad)
    start = -90
    cx, cy = w / 2, h / 2
    radius = (w - 2 * pad) / 2
    for frac, color, label in slices:
        extent = 360 * frac
        draw.pieslice(box, start=start, end=start + extent, fill=color)
        mid = start + extent / 2
        import math
        rad = math.radians(mid)
        lx = cx + math.cos(rad) * (radius * 0.72)
        ly = cy + math.sin(rad) * (radius * 0.72)
        caption = f"{label} {int(frac * 100)}%"
        f = font(22)
        bb = draw.textbbox((0, 0), caption, font=f)
        tw, th = bb[2] - bb[0], bb[3] - bb[1]
        draw.text((lx - tw / 2, ly - th / 2), caption, font=f, fill=WHITE)
        start += extent
    # donut hole for a more modern look
    hole_r = radius * 0.42
    draw.ellipse((cx - hole_r, cy - hole_r, cx + hole_r, cy + hole_r), fill=(246, 247, 250, 255))
    inner = font(28)
    t = "90 days"
    bb = draw.textbbox((0, 0), t, font=inner)
    draw.text((cx - (bb[2] - bb[0]) / 2, cy - (bb[3] - bb[1]) / 2), t, font=inner, fill=INK)
    bg = Image.new("RGB", (w, h), (246, 247, 250))
    bg.paste(im, mask=im.split()[-1])
    return bg


def build_assets() -> dict[str, Path]:
    ASSETS.mkdir(parents=True, exist_ok=True)
    paths = {}
    paths["traction"] = ASSETS / "traction_live.png"
    two_up(
        SHOTS / "06_injection_refusal.png",
        SHOTS / "09_attack_bypass.png",
        (1300, 1378),
    ).save(paths["traction"], quality=95)

    paths["bypass"] = ASSETS / "bypass_live.png"
    framed_shot(SHOTS / "09_attack_bypass.png", (1300, 1284)).save(paths["bypass"], quality=95)

    paths["authorised"] = ASSETS / "authorised_live.png"
    framed_shot(SHOTS / "02_authorised_search.png", (1300, 1378)).save(paths["authorised"], quality=95)

    paths["pie"] = ASSETS / "next_90_pie.png"
    pie_chart((1300, 1284)).save(paths["pie"], quality=95)

    portraits = {
        # fillRect l,t,r,b as percents from the Canva oval crop on slide 13
        "atharva": ("A", "Operations", (46, 92, 184), (650, 975), (-31.470, -20.109, -36.275, -207.199)),
        "kshitij": ("K", "Procurement", (90, 142, 232), (650, 975), (-33.071, -44.787, -26.396, -166.369)),
        "manas": ("M", "Finance", (66, 80, 110), (650, 434), (-34.811, 0.0, -30.352, -43.272)),
        "sahil": ("S", "Support", (82, 140, 168), (650, 434), (-71.203, -9.014, -65.028, -95.591)),
    }
    for key, (initial, role, hue, size, fill_rect) in portraits.items():
        dest = ASSETS / f"team_{key}.jpg"
        team_card(initial, role, size, hue, fill_rect).save(dest, quality=94)
        paths[key] = dest
    return paths


def set_run_text(shape, text: str) -> None:
    tf = shape.text_frame
    if not tf.paragraphs or not tf.paragraphs[0].runs:
        shape.text_frame.text = text
        return
    first = tf.paragraphs[0]
    first.runs[0].text = text
    for run in first.runs[1:]:
        run.text = ""
    for para in tf.paragraphs[1:]:
        for run in para.runs:
            run.text = ""


def shape_text(shape) -> str:
    if not shape.has_text_frame:
        return ""
    return "\n".join(p.text for p in shape.text_frame.paragraphs).strip()


def iter_shapes(shapes):
    for shape in shapes:
        yield shape
        if shape.shape_type == MSO_SHAPE_TYPE.GROUP:
            yield from iter_shapes(shape.shapes)


def replace_picture(shape, path: Path) -> None:
    blip = shape._element.blipFill.blip
    embed = blip.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed")
    image_part = shape.part.related_part(embed)
    image_part._blob = path.read_bytes()


COPY = {
    0: {
        "Startup": "Aegis",
        "Cloudlet Tech": "Aegis",
        "Pitch Deck Presentation": "Agent Security Control Plane",
        "Presented by :": "Presented by :",
        "Adam Fletcher": "Atharva · Kshitij · Manas · Sahil",
    },
    1: {
        "Cloudlet Tech": "Aegis",
        "Today’s Agenda": "Today’s Agenda",
        "Introduction": "The Threat",
        "Problem Statement": "Why Models Fail",
        "Our Innovative Solutions": "The Control Plane",
        "Discover Our Services": "Five Enforcement Layers",
        "Size of Market": "Why This Category",
        "Direct & Indirect Competitor": "Competitive Field",
        "Key Competitive Advantages": "Why We Win",
        "Traction": "Live Proof",
        "Accomplishments Date": "How We Built It",
        "Use of Funds": "What’s Next",
    },
    2: {
        "Introduction": "Introduction",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullam": None,
    },
}


def main() -> None:
    assets = build_assets()
    shutil.copy(TEMPLATE, OUT)
    prs = Presentation(str(OUT))

    slide_copy = [
        # 1 title already via map
        None,
        None,
        {
            "title": "Introduction",
            "left": "Agents now act. They read untrusted pages, plan tool calls, and can email, pay, and export. The model is the planner. It is not the security boundary.",
            "right": "Aegis is the control plane around that planner. Identity, scope, policy, DLP and EDR stay deterministic — even if a 4B local model is jailbroken.",
        },
        {
            "title": "Problem Statement",
            "h1": "PROMPT INJECTION",
            "b1": "Hidden HTML, CSS, comments and documents become the agent’s boss. The page looks clean. The payload is not.",
            "h2": "MODEL ≠ FIREWALL",
            "b2": "Asking the LLM to be careful still lets it propose the email, the export, the purchase. Natural language is not enforcement.",
            "h3": "DETECT ≠ DENY",
            "b3": "A missed finding still needs an action deny. Most stacks stop at prompt filters. Aegis does not.",
        },
        {
            "title": "Our Innovative Solutions",
            "h1": "Scope before planning",
            "b1": "Injection, exfiltration and out-of-domain asks are refused before the model is given a tool-capable task.",
            "h2": "Policy at the tool boundary",
            "b2": "Capability, data labels, destination and approval are deterministic. Every deny carries a stable policy ID.",
            "h3": "Contain the session",
            "b3": "Agent EDR records the run and can quarantine a compromised session so later tools cannot fire.",
        },
        {
            "title": "Discover Our Services",
            "s1": "Identity & RBAC",
            "d1": "Role, clearance and reporting line are data. The model cannot grant itself a tool.",
            "s2": "Scope Guard",
            "d2": "POL-SCOPE-001 and 002 stop prompt injection and sensitive egress before planning starts.",
            "s3": "Policy Firewall",
            "d3": "RBAC, DLP, provenance and approval — independent of whatever the model believed.",
            "s4": "Agent EDR",
            "d4": "A causal trace the judge can read. Containment when the session looks compromised.",
        },
        {
            "title": "Size of Market",
            "body": "Every tool-using agent is a new identity with new authority. The category is not “safer prompts”. It is a control plane: inspect what enters, control what executes, contain what is compromised.",
            "big": "100%",
            "bigcap": "Attack actions blocked — including the detector bypass.",
            "small": "0%",
            "smallcap": "False positives on the benign corpus. Detection can miss. Enforcement does not.",
        },
        {
            "left_title": "Direct Competitor",
            "right_title": "Indirect Competitor",
            "l1": "Prompt filters and LLM-as-judge guards that still trust the model to comply.",
            "l2": "Guardrail SDKs that wrap generation, then hand the agent a live tool handle.",
            "l3": "“Just RAG it” stacks with no action policy and no session containment.",
            "r1": "Classic DLP, EDR and IAM that never see the agent session.",
            "r2": "Browser isolation that stops at fetch and never judges the tool call.",
            "r3": "Human review queues that cannot keep up with machine-speed side effects.",
        },
        {
            "title": "Key Competitive Advantages",
            "h1": "Outside the model",
            "b1": "The 4B planner proposes a short plan only. It has no tool handle and cannot authorise itself.",
            "h2": "Provenance, not vibes",
            "b2": "Facts are labeled EXTERNAL_EVIDENCE. Suspicious text cannot drive an outbound or destructive action.",
            "h3": "Miss and still deny",
            "b3": "Attack detection is 0.75 by design — the bypass counts. Action blocking is 1.0. That is the point.",
        },
        {
            "title": "Traction",
            "body": "Six synthetic Northstar Freight cases, run live in the control room. These are regression checks for the demo — not a production-safety claim.",
            "m1": "100% expected-outcome alignment",
            "m2": "0% workflow drift across six cases",
            "m3": "100% unsafe-request refusal",
        },
        {
            "title": "Accomplishments Date",
            "y1": "Gateway",
            "y2": "Policy",
            "y3": "Tenant",
            "y4": "Now",
            "b1": "Context envelope. Hidden instructions quarantined. Facts kept. Provenance labeled.",
            "b2": "Deterministic action firewall and Agent EDR. Containment when a session looks compromised.",
            "b3": "Northstar Freight: four roles, nine labeled files, three synthetic tools, Q4 model bridge.",
            "b4": "One control room. Judges pick a colleague, send a request, and watch which layer stops them.",
        },
        {
            "title": "Use of Funds",
            "body": "Not a raise. A 90-day build plan to take the hackathon control plane into a pluggable runtime.",
            "l1": "35%  Runtime API and MCP enforcement adapter.",
            "l2": "25%  Red-team corpus: tool-result injection, split payloads, multilingual.",
            "l3": "22%  Model-routing gateway — keep the planner untrusted and swappable.",
            "l4": "18%  Operator UX: toggle every layer live, the way judges already drive the demo.",
        },
        {
            "title": "Meet Our Team",
            "n1": "ATHARVA",
            "n2": "KSHITIJ",
            "n3": "MANAS",
            "n4": "SAHIL",
            "body": "Operations, procurement, finance and support — the same org the control room uses. Role is data, not a slide.",
        },
        {
            "title": "Thank You",
            "brand": "Aegis",
            "sub": "Inspect. Control. Contain.",
            "by": "Presented by :",
            "who": "Atharva · Kshitij · Manas · Sahil",
            "c1": "github.com/theNeuralHorizon/ai-sec",
            "c2": "python -m aegis.webapp",
            "c3": "127.0.0.1:8080",
            "c4": "Northstar Freight · synthetic tenant",
        },
    ]

    # --- slide 1 ---
    s = prs.slides[0]
    by_name = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(by_name["TextBox 5"], "Aegis")
    set_run_text(by_name["TextBox 11"], "Aegis")
    set_run_text(by_name["TextBox 12"], "Agent Security Control Plane")
    set_run_text(by_name["TextBox 14"], "Atharva · Kshitij · Manas · Sahil")

    # --- slide 2 agenda ---
    s = prs.slides[1]
    agenda = {
        "TextBox 14": "Aegis",
        "TextBox 12": "The Threat",
        "TextBox 13": "Why Models Fail",
        "TextBox 16": "The Control Plane",
        "TextBox 18": "Five Enforcement Layers",
        "TextBox 20": "Why This Category",
        "TextBox 22": "Competitive Field",
        "TextBox 24": "Why We Win",
        "TextBox 26": "Live Proof",
        "TextBox 28": "How We Built It",
        "TextBox 30": "What’s Next",
    }
    for name, sh in ((sh.name, sh) for sh in s.shapes if sh.has_text_frame):
        if name in agenda:
            set_run_text(sh, agenda[name])

    # --- slide 3 intro ---
    s = prs.slides[2]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 11"], "Introduction")
    set_run_text(named["TextBox 12"], "Agents now act. They read untrusted pages, plan tool calls, and can email, pay, and export. The model is the planner. It is not the security boundary.")
    set_run_text(named["TextBox 13"], "Aegis is the control plane around that planner. Identity, scope, policy, DLP and EDR stay deterministic — even if a 4B local model is jailbroken.")

    # --- slide 4 problem ---
    s = prs.slides[3]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 8"], "Problem Statement")
    set_run_text(named["TextBox 12"], "Aegis")
    set_run_text(named["TextBox 9"], "PROMPT INJECTION")
    set_run_text(named["TextBox 10"], "MODEL ≠ FIREWALL")
    set_run_text(named["TextBox 11"], "DETECT ≠ DENY")
    set_run_text(named["TextBox 24"], "Hidden HTML, CSS, comments and documents become the agent’s boss. The page looks clean. The payload is not.")
    set_run_text(named["TextBox 25"], "Asking the LLM to be careful still lets it propose the email, the export, the purchase. Language is not enforcement.")
    set_run_text(named["TextBox 26"], "A missed finding still needs an action deny. Most stacks stop at prompt filters. Aegis does not.")

    # --- slide 5 solutions ---
    s = prs.slides[4]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 10"], "Our Innovative Solutions")
    set_run_text(named["TextBox 11"], "Aegis")
    set_run_text(named["TextBox 12"], "Scope before planning")
    set_run_text(named["TextBox 14"], "Injection, exfiltration and out-of-domain asks are refused before the model is given a tool-capable task.")
    set_run_text(named["TextBox 13"], "Policy at the tool boundary")
    set_run_text(named["TextBox 15"], "Capability, labels, destination and approval are deterministic. Every deny carries a stable policy ID.")
    set_run_text(named["TextBox 16"], "Contain the session")
    set_run_text(named["TextBox 17"], "Agent EDR records the run and can quarantine a compromised session so later tools cannot fire.")

    # --- slide 6 services ---
    s = prs.slides[5]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 3"], "Discover Our Services")
    set_run_text(named["TextBox 36"], "Identity & RBAC")
    set_run_text(named["TextBox 37"], "Role, clearance and reporting line are data. The model cannot grant itself a tool.")
    set_run_text(named["TextBox 24"], "Scope Guard")
    set_run_text(named["TextBox 39"], "POL-SCOPE-001 / 002 stop injection and sensitive egress before planning starts.")
    set_run_text(named["TextBox 25"], "Policy Firewall")
    set_run_text(named["TextBox 38"], "RBAC, DLP, provenance and approval — independent of whatever the model believed.")
    set_run_text(named["TextBox 33"], "Agent EDR")
    set_run_text(named["TextBox 34"], "A causal trace the judge can read. Containment when the session looks compromised.")

    # --- slide 7 market ---
    s = prs.slides[6]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 8"], "Size of Market")
    set_run_text(named["TextBox 14"], "Aegis")
    set_run_text(named["TextBox 9"], "Every tool-using agent is a new identity with new authority. The category is not “safer prompts”. It is a control plane.")
    set_run_text(named["TextBox 12"], "100%")
    set_run_text(named["TextBox 10"], "Attack actions blocked — including the detector bypass.")
    set_run_text(named["TextBox 11"], "0%")
    set_run_text(named["TextBox 13"], "False positives on the benign corpus. Detection can miss. Enforcement does not.")

    # --- slide 8 competitors ---
    s = prs.slides[7]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 10"], "Direct Competitor")
    set_run_text(named["TextBox 11"], "Indirect Competitor")
    set_run_text(named["TextBox 12"], "Prompt filters and LLM-as-judge guards that still trust the model to comply.")
    set_run_text(named["TextBox 13"], "Guardrail SDKs that wrap generation, then hand the agent a live tool handle.")
    set_run_text(named["TextBox 14"], "“Just RAG it” stacks with no action policy and no session containment.")
    set_run_text(named["TextBox 15"], "Classic DLP, EDR and IAM that never see the agent session.")
    set_run_text(named["TextBox 16"], "Browser isolation that stops at fetch and never judges the tool call.")
    set_run_text(named["TextBox 17"], "Human review queues that cannot keep up with machine-speed side effects.")

    # --- slide 9 advantages ---
    s = prs.slides[8]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 8"], "Key Competitive Advantages")
    set_run_text(named["TextBox 11"], "Outside the model")
    set_run_text(named["TextBox 13"], "The 4B planner proposes a short plan only. It has no tool handle and cannot authorise itself.")
    set_run_text(named["TextBox 12"], "Provenance, not vibes")
    set_run_text(named["TextBox 14"], "Facts are labeled EXTERNAL_EVIDENCE. Suspicious text cannot drive an outbound action.")
    set_run_text(named["TextBox 15"], "Miss and still deny")
    set_run_text(named["TextBox 16"], "Detection is 0.75 by design — the bypass counts. Action blocking is 1.0. That is the point.")

    # --- slide 10 traction ---
    s = prs.slides[9]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 3"], "Traction")
    set_run_text(named["TextBox 4"], "Six synthetic Northstar Freight cases, run live. Alignment is a regression check for this demo — not a production-safety claim.")
    set_run_text(named["TextBox 11"], "100% expected-outcome alignment")
    set_run_text(named["TextBox 12"], "0% workflow drift across six cases")
    set_run_text(named["TextBox 16"], "100% unsafe-request refusal")
    for sh in iter_shapes(s.shapes):
        if sh.shape_type == MSO_SHAPE_TYPE.PICTURE:
            replace_picture(sh, assets["traction"])

    # --- slide 11 timeline ---
    s = prs.slides[10]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 23"], "Build Timeline")
    set_run_text(named["TextBox 19"], "Gateway")
    set_run_text(named["TextBox 20"], "Policy")
    set_run_text(named["TextBox 21"], "Tenant")
    set_run_text(named["TextBox 22"], "Now")
    set_run_text(named["TextBox 24"], "Context envelope. Hidden instructions quarantined. Facts kept. Provenance labeled.")
    set_run_text(named["TextBox 25"], "Deterministic action firewall and Agent EDR. Containment when a session looks compromised.")
    set_run_text(named["TextBox 26"], "Northstar Freight: four roles, nine labeled files, three synthetic tools, Q4 model bridge.")
    set_run_text(named["TextBox 27"], "One control room. Judges pick a colleague, send a request, and watch which layer stops them.")

    # --- slide 12 funds ---
    s = prs.slides[11]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 6"], "Use of Funds")
    set_run_text(named["TextBox 7"], "Not a raise. A 90-day plan to take the hackathon control plane into a pluggable runtime.")
    set_run_text(named["TextBox 8"], "35%  Runtime API and MCP enforcement adapter.")
    set_run_text(named["TextBox 9"], "25%  Red-team corpus: tool-result injection, split payloads, multilingual.")
    set_run_text(named["TextBox 11"], "22%  Model-routing gateway — keep the planner untrusted and swappable.")
    set_run_text(named["TextBox 12"], "18%  Operator UX: toggle every layer live, the way judges already drive the demo.")
    for sh in iter_shapes(s.shapes):
        if sh.shape_type == MSO_SHAPE_TYPE.PICTURE:
            replace_picture(sh, assets["pie"])

    # --- slide 13 team ---
    s = prs.slides[12]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 26"], "Meet Our Team")
    set_run_text(named["TextBox 27"], "Aegis")
    set_run_text(named["TextBox 28"], "ATHARVA")
    set_run_text(named["TextBox 30"], "KSHITIJ")
    set_run_text(named["TextBox 29"], "MANAS")
    set_run_text(named["TextBox 31"], "SAHIL")
    set_run_text(named["TextBox 32"], "Operations, procurement, finance and support — the same org the control room uses. Role is data, not a slide.")

    team_pics = []
    for sh in iter_shapes(s.shapes):
        if sh.shape_type == MSO_SHAPE_TYPE.PICTURE:
            team_pics.append(sh)
    team_pics.sort(key=lambda sh: (sh.top, sh.left))
    # Four portraits; map by visual order
    mapping = [assets["atharva"], assets["kshitij"], assets["manas"], assets["sahil"]]
    # There may be extra decorative pictures; only replace jpegs that look like photos (taller/wider people)
    photo_like = []
    for sh in team_pics:
        try:
            blip = sh._element.blipFill.blip
            embed = blip.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed")
            part = sh.part.related_part(embed)
            name = Path(part.partname).suffix.lower()
            if name in {".jpeg", ".jpg"}:
                photo_like.append(sh)
        except Exception:
            continue
    photo_like.sort(key=lambda sh: (sh.top, sh.left))
    # Expected order from rels: 25 Atharva-like top-left, 26 top-right?, let's assign by position
    # Top-left, top-right, bottom-left, bottom-right
    if len(photo_like) >= 4:
        ordered = sorted(photo_like, key=lambda sh: (round(sh.top / 100000), sh.left))
        # two rows
        replace_picture(ordered[0], assets["atharva"])
        replace_picture(ordered[1], assets["kshitij"])
        replace_picture(ordered[2], assets["manas"])
        replace_picture(ordered[3], assets["sahil"])

    # --- slide 14 thank you ---
    s = prs.slides[13]
    named = {sh.name: sh for sh in s.shapes if sh.has_text_frame}
    set_run_text(named["TextBox 5"], "Thank You")
    set_run_text(named["TextBox 12"], "Aegis")
    set_run_text(named["TextBox 14"], "Atharva · Kshitij · Manas · Sahil")
    set_run_text(named["TextBox 15"], "Inspect. Control. Contain.")
    set_run_text(named["TextBox 16"], "github.com/theNeuralHorizon/ai-sec")
    set_run_text(named["TextBox 17"], "python -m aegis.webapp")
    set_run_text(named["TextBox 18"], "http://127.0.0.1:8080")
    set_run_text(named["TextBox 19"], "Northstar Freight · synthetic tenant")

    # core props
    prs.core_properties.title = "Aegis — Agent Security Control Plane"
    prs.core_properties.author = "Aegis / Northstar Freight"
    prs.core_properties.subject = "Hackathon pitch deck"
    prs.core_properties.comments = "Filled from the live Aegis control room on main."

    prs.save(str(OUT))
    _replace_team_photos(assets)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


def _replace_team_photos(assets: dict[str, Path]) -> None:
    """Team portraits are image fills inside groups, not Picture shapes."""
    import zipfile
    from io import BytesIO

    mapping = {
        "ppt/media/image25.jpeg": assets["atharva"],
        "ppt/media/image26.jpeg": assets["manas"],
        "ppt/media/image27.jpeg": assets["kshitij"],
        "ppt/media/image28.jpeg": assets["sahil"],
    }
    buf = BytesIO()
    with zipfile.ZipFile(OUT, "r") as src, zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename in mapping:
                data = mapping[item.filename].read_bytes()
            dst.writestr(item, data)
    OUT.write_bytes(buf.getvalue())


if __name__ == "__main__":
    main()
