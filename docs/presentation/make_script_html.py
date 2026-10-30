"""Build "Midterm Script.html" from "Midterm Script.md".

Run from the repository root after every change to the Markdown script:

    uv run python docs/presentation/make_script_html.py
"""

from __future__ import annotations

import html
import re
from pathlib import Path

HERE = Path(__file__).parent
SOURCE = HERE / "Midterm Script.md"
TARGET = HERE / "Midterm Script.html"

SPEAKERS = {"נעם": "a", "אור": "b"}

# English titles exactly as they appear on the slides.
ON_SCREEN = {
    1: "MCP Attack & Defense Simulator",
    2: "What's in this file",
    3: "First: what is an MCP server?",
    4: "Three ways it goes wrong",
    5: "Our goal: put numbers on it",
    6: "Where our ideas came from",
    7: "Our solution: one test bench",
    8: "Six attacks — two of each kind",
    9: "A defense for each attack",
    10: "Example: the poisoned note",
    11: "First results: all six blocked",
    12: "Where we stand",
    13: "Road to the final",
    14: "Questions?",
}

# Parts of the talk, matching the outline slide.
PARTS = [
    ("פתיחה", [1, 2]),
    ("הבעיה", [3, 4]),
    ("המטרה", [5]),
    ("מאיפה הגיעו הרעיונות", [6]),
    ("הפתרון שבנינו", [7, 8, 9]),
    ("תוצאות ראשונות", [10, 11]),
    ("סיכום והמשך", [12, 13, 14]),
]

LATIN = re.compile(
    r"(?<![&#])[A-Za-z][A-Za-z0-9_]*(?:[-.+'][A-Za-z0-9_]+)*"
    r"(?: [A-Za-z0-9][A-Za-z0-9_]*(?:[-.+'][A-Za-z0-9_]+)*)*"
)
CLICK = "**[קליק]**"


def inline(text: str) -> str:
    """Escape one paragraph and apply bold, links and left-to-right English runs."""
    links: list[str] = []

    def keep_link(match: re.Match[str]) -> str:
        target = match.group(1)
        href = target.replace(" ", "%20")
        links.append(f'<a href="{href}" dir="ltr">{html.escape(target)}</a>')
        return f"\x00{len(links) - 1}\x00"

    text = re.sub(r"\[\[([^\]|]+)\]\]", keep_link, text)
    text = html.escape(text, quote=False)
    text = LATIN.sub(lambda m: f'<span class="en" dir="ltr">{m.group(0)}</span>', text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    return re.sub(r"\x00(\d+)\x00", lambda m: links[int(m.group(1))], text)


def seconds(clock: str) -> int:
    minutes, secs = clock.split(":")
    return int(minutes) * 60 + int(secs)


def clock(total: int) -> str:
    return f"{total // 60}:{total % 60:02d}"


def split_sections(lines: list[str]) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = ""
    for line in lines:
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
        elif current and line.strip() != "---":
            sections[current].append(line)
    return sections


def paragraphs(lines: list[str]) -> list[str]:
    text = "\n".join(lines).strip()
    return [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]


def parse_slides(sections: dict[str, list[str]]) -> list[dict[str, object]]:
    head = re.compile(r"שקף (\d+) — (.+?) · (\S+) · (\d+:\d\d)")
    slides = []
    for title, body in sections.items():
        match = head.match(title)
        if match:
            slides.append(
                {
                    "n": int(match.group(1)),
                    "title": match.group(2),
                    "name": match.group(3),
                    "secs": seconds(match.group(4)),
                    "paras": paragraphs(body),
                }
            )
    slides.sort(key=lambda s: int(str(s["n"])))
    return slides


def render_beat(slide: dict[str, object], start: int, previous: str | None) -> str:
    n = int(str(slide["n"]))
    name = str(slide["name"])
    paras = [str(p) for p in slide["paras"]]  # type: ignore[attr-defined]
    clicks = sum(1 for p in paras if p == CLICK)
    end = start + int(str(slide["secs"]))
    click_text = "בלי קליקים" if clicks == 0 else f"{clicks} קליקים"
    if clicks == 1:
        click_text = "קליק אחד"
    title_attr = html.escape(str(slide["title"]))
    out = [
        f'<article class="beat sp-{SPEAKERS[name]}" id="s{n}" data-slide="{n}"'
        + f' data-name="{name}" data-title="{title_attr}">'
    ]
    if previous is not None and previous != name:
        out.append(f'  <div class="handoff-mark">מכאן: {name}</div>')
    out.append(
        "  <header>\n"
        f'    <span class="slideno">שקף {n}</span>\n'
        f'    <span class="who">{name}</span>\n'
        f'    <span class="meta">שקף {n} · <span dir="ltr">{clock(start)}–{clock(end)}</span>'
        f" · {click_text}</span>\n"
        "  </header>"
    )
    out.append(f'  <h3>{inline(str(slide["title"]))}</h3>')
    out.append(
        f'  <div class="screen">על המסך: <span dir="ltr">{html.escape(ON_SCREEN[n])}</span></div>'
    )
    count = 0
    for p in paras:
        if p == CLICK:
            count += 1
            out.append(f'  <div class="click"><span>קליק {count}</span></div>')
        else:
            out.append(f"  <p>{inline(p)}</p>")
    out.append("</article>")
    return "\n".join(out)


def render_qa(lines: list[str]) -> str:
    items = []
    for block in paragraphs(lines):
        question, _, answer = block.partition("\n")
        question = question.strip().strip("*").strip('"')
        items.append(
            '<details class="qa">\n'
            f"  <summary>{inline(question)}</summary>\n"
            f"  <p>{inline(answer.strip())}</p>\n"
            "</details>"
        )
    return "\n".join(items)


def render_checklist(lines: list[str]) -> str:
    items = [line[2:].strip() for line in lines if line.startswith("- ")]
    return (
        '<ul class="check">\n'
        + "\n".join(f"  <li>{inline(i)}</li>" for i in items)
        + "\n</ul>"
    )


def build() -> str:
    text = SOURCE.read_text(encoding="utf-8")
    body = text.split("---", 2)[2] if text.startswith("---") else text
    sections = split_sections(body.splitlines())
    slides = parse_slides(sections)
    by_n = {int(str(s["n"])): s for s in slides}

    starts: dict[int, int] = {}
    t = 0
    for s in slides:
        starts[int(str(s["n"]))] = t
        t += int(str(s["secs"]))
    total = t
    per = {name: 0 for name in SPEAKERS}
    for s in slides:
        per[str(s["name"])] += int(str(s["secs"]))
    clicks = sum(
        1 for s in slides for p in s["paras"] if p == CLICK  # type: ignore[attr-defined]
    )

    rows = []
    for s in slides:
        n = int(str(s["n"]))
        name = str(s["name"])
        rows.append(
            f'<tr><td><a href="#s{n}">{n}</a></td><td><a href="#s{n}">{inline(str(s["title"]))}</a></td>'
            f'<td class="who-{SPEAKERS[name]}">{name}</td>'
            f'<td dir="ltr">{clock(starts[n])}</td><td dir="ltr">{clock(int(str(s["secs"])))}</td></tr>'
        )

    parts = []
    previous: str | None = None
    for part, numbers in PARTS:
        beats = []
        for n in numbers:
            beats.append(render_beat(by_n[n], starts[n], previous))
            previous = str(by_n[n]["name"])
        parts.append(f"<section><h2>{part}</h2>\n" + "\n".join(beats) + "\n</section>")

    summary = (
        f'{len(slides)} שקפים · כ-<span dir="ltr">{clock(total)}</span> דקות, ועוד זמן לשאלות · '
        f'נעם <span dir="ltr">{clock(per["נעם"])}</span>, אור <span dir="ltr">{clock(per["אור"])}</span> · '
        f"{clicks} קליקים"
    )
    page = TEMPLATE
    for key, value in {
        "@@SUMMARY@@": summary,
        "@@ROWS@@": "\n".join(rows),
        "@@PARTS@@": "\n\n".join(parts),
        "@@QA@@": render_qa(sections["הכנה לשאלות"]),
        "@@CHECK@@": render_checklist(sections["לפני ההצגה"]),
    }.items():
        page = page.replace(key, value)
    return page


TEMPLATE = """<!doctype html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>תסריט מצגת אמצע</title>
<style>
  :root {
    --bg: #ffffff; --text: #16181d; --muted: #5c6370; --line: #dde1e6; --card: #f6f7f9;
    --a: #1f4e9c; --b: #8a4b08; --red: #c0261e; --code-bg: #eceff3; --line-strong: #9aa1ab;
    --size: 19px;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #15171b; --text: #e8eaed; --muted: #9aa1ab; --line: #2c3036; --card: #1d2025;
      --a: #8fb4f0; --b: #e7b07a; --red: #f0857e; --code-bg: #262a31; --line-strong: #5c6370;
    }
  }
  :root[data-theme="dark"] {
    --bg: #15171b; --text: #e8eaed; --muted: #9aa1ab; --line: #2c3036; --card: #1d2025;
    --a: #8fb4f0; --b: #e7b07a; --red: #f0857e; --code-bg: #262a31; --line-strong: #5c6370;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: Arial, "Segoe UI", "Noto Sans Hebrew", sans-serif;
    font-size: var(--size); line-height: 1.75;
  }
  main { max-width: 820px; margin: 0 auto; padding: 0 16px 80px; }
  a { color: inherit; }
  .top {
    position: sticky; top: 0; z-index: 2; background: var(--bg);
    border-bottom: 1px solid var(--line); padding: 12px 0 10px;
  }
  h1 { font-size: 1.35em; margin: 0 0 4px; }
  .summary { color: var(--muted); font-size: 0.8em; }
  .controls { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  .controls button {
    font: inherit; font-size: 0.78em; padding: 4px 12px; border-radius: 6px; cursor: pointer;
    border: 1px solid var(--line); background: var(--card); color: var(--text);
  }
  .controls button[aria-pressed="true"] { border-color: var(--text); font-weight: bold; }
  .howto {
    margin: 22px 0 0; padding: 12px 18px; border-radius: 8px; background: var(--card);
    font-size: 0.85em;
  }
  .howto ul { margin: 0; padding-inline-start: 20px; }
  h2 {
    font-size: 1em; color: var(--muted); font-weight: bold; margin: 40px 0 12px;
    padding-bottom: 6px; border-bottom: 1px solid var(--line);
  }
  .beat {
    background: var(--card); border-radius: 8px; padding: 16px 20px 6px; margin: 0 0 14px;
    border-inline-start: 4px solid transparent; scroll-margin-top: 150px;
  }
  .beat.sp-a { border-inline-start-color: var(--a); }
  .beat.sp-b { border-inline-start-color: var(--b); }
  .beat header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 14px; }
  .who { font-weight: bold; font-size: 0.85em; }
  .sp-a .who, .who-a { color: var(--a); font-weight: bold; }
  .sp-b .who, .who-b { color: var(--b); font-weight: bold; }
  .meta { color: var(--muted); font-size: 0.75em; }
  .beat h3 { font-size: 0.95em; margin: 4px 0 0; }
  .screen { color: var(--muted); font-size: 0.75em; margin: 0 0 10px; }
  .beat p { margin: 0 0 12px; }
  .click { margin: 2px 0 12px; display: flex; align-items: center; gap: 10px; }
  .click::after { content: ""; flex: 1; border-top: 1px dashed var(--line-strong); }
  .click span {
    font-size: 0.72em; font-weight: bold; color: var(--red); border: 1.5px solid var(--red);
    border-radius: 999px; padding: 0 10px; white-space: nowrap;
  }
  .handoff-mark {
    font-weight: bold; font-size: 0.78em; color: var(--muted); margin: 0 0 6px;
  }
  .en { white-space: nowrap; }
  body.only-a .beat.sp-b, body.only-b .beat.sp-a { display: none; }
  table { width: 100%; border-collapse: collapse; font-size: 0.82em; }
  th, td { text-align: right; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: bold; }
  td a { text-decoration: none; }
  td a:hover { text-decoration: underline; }
  .qa { background: var(--card); border-radius: 8px; margin: 0 0 10px; padding: 10px 18px; }
  .qa summary { cursor: pointer; font-weight: bold; }
  .qa p { margin: 8px 0 4px; }
  .check { padding-inline-start: 22px; }
  .check li { margin-bottom: 8px; }
  .note { color: var(--muted); font-size: 0.78em; margin-top: 30px; }
  code { font-family: Consolas, "Cascadia Mono", monospace; font-size: 0.86em; background: var(--code-bg); padding: 1px 5px; border-radius: 4px; }

  /* presenting mode: every slide in large type, one under the other. Moved with the
     wheel or the buttons, so the keyboard can stay with the deck */
  .recbar, .recnav, .slideno { display: none; }
  body.rec .top, body.rec h2, body.rec .howto, body.rec .extra { display: none; }
  body.rec main { max-width: 980px; padding-bottom: 75vh; }
  body.rec .beat {
    background: none; border-radius: 0; margin: 0; padding: 14px 0 6px;
    border-inline-start: none; border-top: 3px solid var(--line-strong); scroll-margin-top: 64px;
  }
  body.rec .beat.current { border-top-color: var(--red); }
  body.rec .beat header .meta, body.rec .screen { display: none; }
  body.rec .slideno { display: inline; font-weight: bold; font-size: 1.25em; }
  body.rec .beat .who { font-size: 1em; }
  body.rec .beat h3 { color: var(--muted); font-weight: normal; }
  body.rec .beat p { font-size: 1.3em; line-height: 1.8; }
  body.rec .click span { font-size: 1em; }
  body.rec .handoff-mark {
    font-size: 1em; color: var(--text); padding: 6px 12px; margin: 0 0 10px; border-radius: 6px;
    background: var(--code-bg);
  }
  body.rec .recbar {
    display: flex; align-items: center; gap: 12px; position: sticky; top: 0; z-index: 2;
    background: var(--bg); border-bottom: 1px solid var(--line); padding: 10px 0; margin-bottom: 18px;
  }
  .recbar .where { font-weight: bold; font-size: 1.15em; flex: 1; }
  .recbar .next-info { color: var(--muted); font-size: 0.8em; }
  .recbar button, .recnav button {
    font: inherit; padding: 6px 16px; border-radius: 6px; cursor: pointer;
    border: 1px solid var(--line); background: var(--card); color: var(--text);
  }
  body.rec .recnav {
    display: flex; gap: 12px; position: fixed; bottom: 0; inset-inline: 0; z-index: 2;
    background: var(--bg); border-top: 1px solid var(--line); padding: 8px 16px; justify-content: center;
  }
  .recnav button { padding: 10px 28px; min-width: 120px; }
  @media (max-width: 600px) {
    :root { --size: 17px; } .beat { padding: 14px 14px 4px; }
    .table-wrap { overflow-x: auto; }
  }
  @media print {
    .top { position: static; } .controls, .recbar, .recnav { display: none !important; }
    .beat { break-inside: avoid; background: none; border: 1px solid #ccc; }
    .qa { background: none; border: 1px solid #ccc; }
    body { font-size: 13pt; }
  }
</style>
</head>
<body>
<main>
  <div class="top">
    <h1>תסריט מצגת אמצע — מילה במילה</h1>
    <div class="summary">@@SUMMARY@@</div>
    <div class="controls">
      <button id="rec-start"><b>מצב הצגה</b></button>
      <button data-filter="all" aria-pressed="true">כולם</button>
      <button data-filter="a" aria-pressed="false">רק נעם</button>
      <button data-filter="b" aria-pressed="false">רק אור</button>
      <button id="bigger">אותיות גדולות יותר</button>
      <button id="smaller">אותיות קטנות יותר</button>
    </div>
  </div>
  <div class="recbar">
    <span class="where"><span id="rec-where"></span><br><span class="next-info" id="rec-next-info"></span></span>
    <button id="rec-smaller">א-</button>
    <button id="rec-bigger">א+</button>
    <button id="rec-exit">יציאה</button>
  </div>

  <div class="howto">
    <ul>
      <li>השקפים באנגלית, ההרצאה בעברית. המצגת: <a href="Midterm%20Deck.html" dir="ltr">Midterm Deck.html</a>, באותה תיקייה.</li>
      <li><b style="color:var(--red)">קליק</b> = חץ ימינה, רווח או קליקר. כל קליק חושף את הפריט הבא בשקף; בסוף השקף הקליק עובר לשקף הבא.</li>
      <li>מתחלפים בכל חלק. משפט ההעברה מופיע בסוף כל חלק.</li>
      <li><b>מצב הצגה</b>: כל השקפים באותיות גדולות, אחד מתחת לשני. גוללים עם הגלגלת או עם הכפתורים למטה. לחיצה כפולה על שקף פותחת את מצב ההצגה ממנו.</li>
    </ul>
  </div>

  <section class="extra">
    <h2>מי אומר מה</h2>
    <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>שקף</th><th>מציג</th><th>מתחיל ב-</th><th>אורך</th></tr></thead>
      <tbody>
@@ROWS@@
      </tbody>
    </table>
    </div>
  </section>

@@PARTS@@

  <div class="recnav">
    <button id="rec-prev">הקודם</button>
    <button id="rec-next">הבא</button>
  </div>

  <section class="extra">
    <h2>הכנה לשאלות</h2>
@@QA@@
  </section>

  <section class="extra">
    <h2>לפני ההצגה</h2>
@@CHECK@@
    <p class="note">נוצר מתוך <code dir="ltr">Midterm Script.md</code> בעזרת <code dir="ltr">make_script_html.py</code>.
    אחרי כל שינוי בתסריט מריצים את הסקריפט שוב.</p>
  </section>
</main>
<script>
  (function () {
    var body = document.body, root = document.documentElement;
    function store(k, v) { try { localStorage.setItem('midterm-' + k, v); } catch (e) {} }
    function load(k) { try { return localStorage.getItem('midterm-' + k); } catch (e) { return null; } }
    function setFilter(f) {
      body.classList.remove('only-a', 'only-b');
      if (f === 'a' || f === 'b') body.classList.add('only-' + f);
      document.querySelectorAll('[data-filter]').forEach(function (b) {
        b.setAttribute('aria-pressed', String(b.dataset.filter === f));
      });
      store('filter', f);
    }
    function setSize(px) {
      px = Math.max(14, Math.min(34, px));
      root.style.setProperty('--size', px + 'px');
      store('size', String(px));
    }
    function current() { return parseFloat(getComputedStyle(root).getPropertyValue('--size')) || 19; }
    document.querySelectorAll('[data-filter]').forEach(function (b) {
      b.addEventListener('click', function () { setFilter(b.dataset.filter); });
    });
    document.getElementById('bigger').addEventListener('click', function () { setSize(current() + 2); });
    document.getElementById('smaller').addEventListener('click', function () { setSize(current() - 2); });
    var f = load('filter'); if (f) setFilter(f);
    var s = parseFloat(load('size')); if (s) setSize(s);

    var beats = Array.prototype.slice.call(document.querySelectorAll('.beat'));
    var idx = Math.min(beats.length - 1, Math.max(0, parseInt(load('idx'), 10) || 0));
    var bar = document.querySelector('.recbar');
    function visible() { return beats.filter(function (b) { return b.offsetParent !== null; }); }
    function label(b) {
      idx = beats.indexOf(b);
      beats.forEach(function (x) { x.classList.toggle('current', x === b); });
      document.getElementById('rec-where').textContent =
        'שקף ' + b.dataset.slide + ' מתוך ' + beats.length + ' · ' + b.dataset.name;
      var n = beats[idx + 1], info = 'זה השקף האחרון';
      if (n) {
        info = 'הבא: שקף ' + n.dataset.slide + ', ' + n.dataset.title;
        if (n.dataset.name !== b.dataset.name) info = 'אחריו ' + n.dataset.name + ' · ' + info;
      }
      document.getElementById('rec-next-info').textContent = info;
      store('idx', String(idx));
    }
    function go(step) {
      var v = visible(), i = v.indexOf(beats[idx]);
      var b = v[Math.min(v.length - 1, Math.max(0, (i < 0 ? 0 : i) + step))] || beats[0];
      b.scrollIntoView({ block: 'start' });
      label(b);
      if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
    }
    var ticking = false;
    window.addEventListener('scroll', function () {
      if (!body.classList.contains('rec') || ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        ticking = false;
        var line = bar.getBoundingClientRect().bottom + 40, cur = null;
        visible().forEach(function (b) { if (b.getBoundingClientRect().top <= line) cur = b; });
        if (cur && cur !== beats[idx]) label(cur);
      });
    });
    function rec(on) {
      body.classList.toggle('rec', on);
      if (on) go(0); else beats[idx].scrollIntoView({ block: 'start' });
    }
    document.getElementById('rec-start').addEventListener('click', function () { rec(true); });
    document.getElementById('rec-exit').addEventListener('click', function () { rec(false); });
    document.getElementById('rec-next').addEventListener('click', function () { go(1); });
    document.getElementById('rec-prev').addEventListener('click', function () { go(-1); });
    document.getElementById('rec-bigger').addEventListener('click', function () { setSize(current() + 2); });
    document.getElementById('rec-smaller').addEventListener('click', function () { setSize(current() - 2); });
    beats.forEach(function (b, j) {
      b.addEventListener('dblclick', function () { if (!body.classList.contains('rec')) { idx = j; rec(true); } });
    });
    document.addEventListener('keydown', function (e) {
      if (!body.classList.contains('rec')) return;
      if ([' ', 'PageDown', 'ArrowLeft'].indexOf(e.key) >= 0) { e.preventDefault(); go(1); }
      else if (['PageUp', 'ArrowRight', 'Backspace'].indexOf(e.key) >= 0) { e.preventDefault(); go(-1); }
      else if (e.key === 'Escape') rec(false);
    });
  })();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    TARGET.write_text(build(), encoding="utf-8")
    print(f"wrote {TARGET.name}")
