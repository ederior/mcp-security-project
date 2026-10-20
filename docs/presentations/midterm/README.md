# Midterm presentation (October 2026)

Source files for the midterm deck "MCP Attack & Defense Simulator — Midterm".
The slides are in English; the talk is given in Hebrew.

- Live deck (private until shared): https://claude.ai/artifact/RfV4n2ZgLT5r6ZHk4qvg7Y
- `MCP Attack & Defense Simulator — Midterm.pptx`: PowerPoint export of the
  live deck (13 slides with speaker notes), exported 20 October 2026. It has
  no click animations: every slide appears complete at once, and the cover
  animation is a still image. Re-export after any change to the live deck.
- `deck.json`: slide order, sections and fonts.
- `slides/<id>.html`: one file per slide, with speaker notes in the `<aside>` at the end.

These files use the deck tool's slide format (`x-icon`, `x-connector`, `x-embed`),
so they do not render correctly when opened directly in a browser. To keep the
animations, present from the live deck in Present mode; the `.pptx` is the
offline fallback.

## Before presenting

- Fill in the semester, date and task dates (`[...]` placeholders).
- Add the ECE faculty and Technion logos to the two frames on the cover.
- Rerun the test suite: the results slide reflects Or's local run from
  10 October 2026, and CI is currently red on a type check.
- Replace `n.d.` in the literature citations if a source page has a date.
