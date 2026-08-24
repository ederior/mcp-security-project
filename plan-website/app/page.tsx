'use client';

import { useState } from 'react';

type Owner = 'all' | 'or' | 'noam' | 'joint';

const roadmap = [
  { phase: '0', owner: 'joint', id: 'J0.1–J0.4', title: 'איפוס משותף', detail: 'מאשרים תחום, מתקנים 14←15 איומים, פותחים Issues ומגינים על main.', gate: 'כל ההחלטות מתועדות ב־DECISIONS.md.' },
  { phase: '1', owner: 'or', id: 'O1.1–O1.3', title: 'הגירת הפרוטוטייפ', detail: 'מבנה src, מעבר server/client/demo והפיכת הבדיקות החיות להדגמה ידנית.', gate: 'ההתנהגות הקיימת נשמרת ואין קוד אפליקטיבי בשורש.' },
  { phase: '1', owner: 'noam', id: 'N1.1–N1.3', title: 'תכנון ניסויים והגנות', detail: 'מטריצת מדדים, גודל מדגם, קטלוג הגנות ומסמכי מדיניות מוכנים ב־Vault.', gate: 'אור מאשר את התכנון לפני ההטמעה.' },
  { phase: '2', owner: 'joint', id: 'J2.1', title: 'הקפאת החוזים', detail: 'Scenario, ToolEvent, AttackResult, DetectionVerdict ו־RunResult.', gate: 'PR חוזים קטן ומאושר בידי שניכם.' },
  { phase: '2', owner: 'noam', id: 'N2.1–N2.3', title: 'צינור ניסוי ירוק', detail: 'Fake backend, טעינת YAML, smoke scenario, לוגים מובנים ו־CI.', gate: 'pytest, ruff, black ו־mypy ירוקים.' },
  { phase: '2', owner: 'or', id: 'O2.1–O2.2', title: 'Session ואירועים', detail: 'חיבור מתמשך, user/session binding ואירוע ToolEvent מחוטא לכל קריאה.', gate: 'כמה קריאות כלים חולקות הקשר זהות מפורש.' },
  { phase: '3', owner: 'or', id: 'O3.1–O3.3', title: 'התקפה ראשונה מכל משפחה', detail: 'AC-PI1a, AC-SH1a, AC-CL1a עם YAML ובדיקת הצלחה ללא הגנה.', gate: 'כל התקפה מצליחה באופן דטרמיניסטי במצב none.' },
  { phase: '3', owner: 'noam', id: 'N3.1–N3.3', title: 'הגנה ראשונה מכל משפחה', detail: 'Detector, mitigation, בדיקת חסימה ובדיקות benign לכל שלוש המשפחות.', gate: 'יש verdict, הסבר, FPR וזמן ריצה.' },
  { phase: '4', owner: 'or', id: 'O4.1–O4.3', title: 'הווריאציות השניות', detail: 'AC-PI2a, AC-SH3a, AC-CL2a — שונות מהותית מהתרחישים הראשונים.', gate: 'שש התקפות הליבה רצות מקצה לקצה.' },
  { phase: '4', owner: 'noam', id: 'N4.1–N4.3', title: 'ניסויים כמותיים', detail: 'LLM judge לתוכן, corpus תקין, FPR/FNR, שלושה מצבי הגנה וגרפים.', gate: 'CSV/JSON ותיקיות ריצה ניתנים לשחזור.' },
  { phase: '5', owner: 'or', id: 'O5.1–O5.2', title: 'אימות והדגמה', detail: 'Spot validation עם Gemini והדגמה מקומית אמינה עם fallback.', gate: 'כל טענה בהדגמה תואמת לקוד ולארכיטקטורה.' },
  { phase: '5', owner: 'noam', id: 'N5.1–N5.2', title: 'ניתוח ותוצרי מסירה', detail: 'טבלאות, גרפים, מתודולוגיה, תוצאות ומגבלות לדוח.', gate: 'כל נתון מציין backend, מדגם, seed ואי־ודאות.' },
  { phase: '5', owner: 'joint', id: 'J5.1', title: 'סקירה וחזרה גנרלית', detail: 'מעקב מכל טענת מצגת אל קוד, ריצה או מקור; הכנת גיבוי לדמו.', gate: 'שניכם מאשרים את הדוח והמצגת.' },
];

const ownerLabel: Record<Exclude<Owner, 'all'>, string> = { or: 'אור', noam: 'נעם', joint: 'משותף' };

export default function Home() {
  const [owner, setOwner] = useState<Owner>('all');
  const [checked, setChecked] = useState<boolean[]>([false, false, false, false, false]);
  const visibleTasks = owner === 'all' ? roadmap : roadmap.filter((task) => task.owner === owner);
  const doneCount = checked.filter(Boolean).length;

  return (
    <main dir="rtl">
      <section className="hero" id="top">
        <nav className="nav shell" aria-label="ניווט ראשי">
          <a className="brand" href="#top" aria-label="חזרה לראש העמוד">
            <span className="brand-mark">M</span>
            <span><b>MCP Security</b><small>תוכנית עבודה סופית</small></span>
          </a>
          <div className="nav-links">
            <a href="#status">מצב נוכחי</a><a href="#scope">תחום</a><a href="#ownership">אחריות</a><a href="#roadmap">ביצוע</a><a href="#start">מתחילים</a>
          </div>
          <button className="print-button" type="button" onClick={() => window.print()} title="הדפסת התוכנית" aria-label="הדפסת התוכנית">↗ PDF</button>
        </nav>

        <div className="shell hero-grid">
          <div>
            <p className="eyebrow">PROJECT A · 00440167 · גרסה סופית לעבודה</p>
            <h1>מפרוטוטייפ עובד<br /><em>למחקר מדיד.</em></h1>
            <p className="lead">מפת עבודה אחת, ברורה ולא חופפת, שמחברת בין מה שאור כבר בנה לבין הסימולטור, הניסויים וההגנות שנעם ואור צריכים להשלים יחד.</p>
            <div className="hero-actions">
              <a className="button primary" href="#ownership">מי עושה מה ←</a>
              <a className="button secondary" href="#roadmap">לציר הזמן</a>
            </div>
          </div>

          <aside className="decision-card" aria-label="החלטת הפרויקט">
            <span className="card-label">החלטת העל</span>
            <h2>לא מתחילים מחדש.</h2>
            <p>שומרים את שרת ה־MCP, לולאת Gemini, ההדגמה וההזרקה שכבר עובדים — ומעבירים אותם למבנה מחקרי לפני שמוסיפים התקפות חדשות.</p>
            <div className="mini-grid">
              <div><strong>6</strong><span>וריאציות ליבה</span></div><div><strong>3</strong><span>משפחות איום</span></div><div><strong>5</strong><span>שלבי ביצוע</span></div>
            </div>
          </aside>
        </div>
      </section>

      <section className="audit-strip" aria-label="פרטי האודיט">
        <div className="shell audit-grid">
          <div><b>24.08.2026</b><span>תאריך האודיט</span></div><div><b>main נקי</b><span>מסונכרן עם origin</span></div><div><b>6 commits</b><span>כולם מאת אור</span></div><div><b>9 קבצים</b><span>נקראו במלואם</span></div><div><b>5/5</b><span>קובצי Python עוברים parse</span></div>
        </div>
      </section>

      <section className="section shell" id="status">
        <div className="section-heading">
          <p className="eyebrow dark">איפה אתם עומדים</p>
          <h2>יש בסיס אמיתי. חסרה שכבת המחקר.</h2>
          <p>המאגר הוא פרוטוטייפ טוב להזרקת פקודות: הוא מוכיח ש־Gemini יכול לקרוא פלט כלי זדוני ולבצע קריאה לא רצויה. הוא עדיין לא סביבת ניסוי ניתנת לשחזור.</p>
        </div>

        <div className="what-exists">
          <article><span className="number">01</span><h3>שרת MCP עובד</h3><p><code>server.py</code> מציע חמישה כלים, resource מקומי ונתונים פיקטיביים דרך Streamable HTTP.</p></article>
          <article><span className="number">02</span><h3>סוכן Gemini עובד</h3><p><code>ai_client.py</code> ממיר כלים לסכמות, מריץ עד חמש קריאות ומחזיר את התוצאות למודל.</p></article>
          <article><span className="number">03</span><h3>הדגמת Injection</h3><p><code>note_4</code> גורמת במצב לא מוגן לקריאת פרופיל של משתמש אחר — AC-PI1a / AC-PI4a.</p></article>
          <article><span className="number">04</span><h3>ממשק ומסמכים</h3><p>קיים צ׳אט אינטראקטיבי, README בסיסי ודוח קצר שמשווים secure מול unsafe.</p></article>
        </div>

        <div className="gap-board" aria-label="פערים מול התוכנית">
          <div className="gap-head"><span>דרישה</span><span>מצב</span><span>המשמעות המעשית</span></div>
          {[
            ['שרת ולקוח MCP', 'חלקי חזק', 'לארוז במבנה src ולהוסיף session, identity ואירועים מובנים.'],
            ['Prompt Injection', '1 מתוך 2', 'לשמר AC-PI1a ולהוסיף AC-PI2a ישיר ונפרד.'],
            ['Session Hijacking', 'חסר', 'לממש התחזות AC-SH1a ו־replay AC-SH3a.'],
            ['Credential Leakage', 'סמוך בלבד', 'פרופיל פיקטיבי אינו secret; לשתול canary ולהוסיף CL1a/CL2a.'],
            ['Detectors + Mitigations', 'חסר', 'secure prompt הוא baseline בלבד, לא הגנה אכיפה ומדידה.'],
            ['Fake backend + pytest', 'דחוף', 'הבדיקות הנוכחיות חיות, יקרות ולא דטרמיניסטיות.'],
            ['Harness + metrics', 'חסר', 'נדרשים ASR, FPR/FNR, effectiveness, latency ו־artifacts.'],
            ['Tooling + CI', 'חסר', 'לעבור ל־uv ולהפעיל pytest, ruff, black ו־mypy.'],
          ].map(([req, state, meaning], i) => <div className="gap-row" key={req}><b>{req}</b><span className={`pill p${i}`}>{state}</span><p>{meaning}</p></div>)}
        </div>

        <aside className="finding-callout">
          <b>הערת דיוק חשובה</b>
          <p>מסמכי התכנון אומרים “14 איומים”, אבל הטבלאות מכילות בפועל <strong>15</strong>. מתקנים את המספר בכל המסמכים לפני ההעתקה למאגר.</p>
        </aside>
      </section>

      <section className="section scope-section" id="scope">
        <div className="shell">
          <div className="section-heading">
            <p className="eyebrow dark">הקפאת תחום</p>
            <h2>שש וריאציות ליבה. כל השאר ממתין.</h2>
            <p>היקף קטן אך שלם עדיף על קטלוג רחב ללא תוצאות. כל משפחה מקבלת התקפה בסיסית, התקפה שנייה, detector, mitigation ומדידה.</p>
          </div>
          <div className="family-grid">
            <article className="family-card pi"><span className="family-code">PI</span><h3>Prompt Injection</h3><div><b>AC-PI1a</b><p>הזרקה עקיפה מתוך note זדוני — הפרוטוטייפ הקיים.</p></div><div><b>AC-PI2a</b><p>הוראת override ישירה ממשתמש זדוני.</p></div><footer>LLM judge + כלל תוכן + policy לכלים</footer></article>
            <article className="family-card sh"><span className="family-code">SH</span><h3>Session Hijacking</h3><div><b>AC-SH1a</b><p>התחזות בגלל session שאינו קשור נכון לזהות.</p></div><div><b>AC-SH3a</b><p>Replay של פעולה תקינה שכבר בוצעה.</p></div><footer>Binding validator + nonce / sequence</footer></article>
            <article className="family-card cl"><span className="family-code">CL</span><h3>Credential Leakage</h3><div><b>AC-CL1a</b><p>דליפת fake secret דרך output או context.</p></div><div><b>AC-CL2a</b><p>Injection שולחת secret ליעד מקומי ואינרטי.</p></div><footer>Scanner + redaction + output policy</footer></article>
          </div>
          <div className="scope-foot">
            <div><b>תוספת זולה</b><p>AC-CL4a — סריקת structured logs לאיתור canary.</p></div>
            <div><b>Stretch בלבד</b><p>וריאציות נוספות, SSRF, token passthrough וכל ההתקפות מבוססות התמונה.</p></div>
          </div>
        </div>
      </section>

      <section className="section architecture" id="architecture">
        <div className="shell architecture-grid">
          <div>
            <p className="eyebrow">ארכיטקטורת היעד</p>
            <h2>מסלול אחד מן התרחיש ועד המדד.</h2>
            <p className="architecture-copy">ה־Harness טוען Scenario, מפעיל backend וסוכן, אוסף ToolEvent, מריץ Detector ו־Mitigation, ולבסוף שומר RunResult בר־שחזור.</p>
            <div className="flow" aria-label="זרימת הניסוי">
              {['Scenario YAML', 'Harness', 'LLM + MCP', 'Detection', 'Mitigation', 'Metrics'].map((item, i) => <div key={item}><span>{String(i + 1).padStart(2, '0')}</span><b>{item}</b></div>)}
            </div>
          </div>
          <pre className="tree" dir="ltr" aria-label="מבנה התיקיות המתוכנן"><code>{`mcp-security-project/
├─ src/
│  ├─ contracts/
│  ├─ mcp_server/        # Or
│  ├─ mcp_client/        # Or
│  ├─ llm_backend/       # Noam
│  ├─ attacks/           # Or
│  ├─ defenses/          # Noam
│  └─ harness/           # Noam
├─ scenarios/
│  ├─ attacks/           # Or
│  └─ benign/            # Noam
├─ experiments/          # Noam
├─ tests/
├─ references/
├─ docs/
├─ examples/
└─ results/              # ignored`}</code></pre>
        </div>
      </section>

      <section className="section shell contracts" id="contracts">
        <div className="section-heading">
          <p className="eyebrow dark">גבול האינטגרציה</p>
          <h2>מקפיאים חמישה חוזים לפני עבודה מקבילית.</h2>
          <p>שינוי בחוזה עובר PR קטן ונפרד. כך אף אחד לא צריך לנחש איך החצי של השני נראה.</p>
        </div>
        <div className="contract-grid">
          <details open><summary>Scenario</summary><p><code>scenario_id · family · variant_id · seed · backend · defense_mode · user_prompt · tool_data · expected_signals · max_tool_rounds</code></p></details>
          <details><summary>ToolEvent</summary><p><code>timestamp · run_id · tool_name · sanitized_args · sanitized_result_metadata · session/user · latency · blocked/allowed</code></p></details>
          <details><summary>AttackResult</summary><p><code>success · matched_signals · unexpected_tool_calls · leaked_canary · reason</code></p></details>
          <details><summary>DetectionVerdict</summary><p><code>verdict · confidence · reason · detector_name/version · latency</code></p></details>
          <details><summary>RunResult</summary><p><code>scenario_config · git_sha · seed · attack_result · verdicts · mitigation_result · total_latency · artifact_paths</code></p></details>
        </div>
      </section>

      <section className="section ink" id="ownership">
        <div className="shell">
          <div className="section-heading light">
            <p className="eyebrow">כלל אי־כפילות</p>
            <h2>אור בונה את התוקף. נעם בונה את המגן והמעבדה.</h2>
            <p>חלוקת האחריות נעשית לפי גבולות מערכת וקבצים — לא לפי “מי פנוי עכשיו”.</p>
          </div>
          <div className="owner-grid">
            <article className="owner-card or">
              <div className="owner-top"><span className="avatar">א</span><div><small>מערכת היעד + התקפות</small><h3>אור</h3></div></div>
              <ul><li>מיגרציית שרת, לקוח והדגמה</li><li>Session מתמשך וקישור זהות</li><li>שש התקפות ו־attack YAML</li><li>בדיקות הצלחה במצב לא מוגן</li><li>אירועים מחוטאים ו־Gemini demo</li></ul>
              <code className="path-list" dir="ltr">src/mcp_server/** · src/mcp_client/** · src/attacks/** · scenarios/attacks/** · tests/server/** · tests/attacks/** · examples/**</code>
            </article>
            <article className="owner-card noam">
              <div className="owner-top"><span className="avatar">נ</span><div><small>ניסויים + הגנות</small><h3>נעם</h3></div></div>
              <ul><li>Backend interface ו־Fake דטרמיניסטי</li><li>Harness, לוגים, מדדים ותיקיות ריצה</li><li>Detectors ו־mitigations</li><li>Benign corpus ובדיקות FPR/FNR</li><li>ניסויים, טבלאות, גרפים ו־CI</li></ul>
              <code className="path-list" dir="ltr">src/llm_backend/** · src/defenses/** · src/harness/** · scenarios/benign/** · experiments/** · tests/defenses/** · tests/harness/** · tests/integration/**</code>
            </article>
          </div>
          <div className="shared-rules">
            <h3>קבצים משותפים — עורך יחיד, reviewer יחיד</h3>
            <div><span><b>Contracts</b> PR ייעודי; שניכם מאשרים</span><span><b>CLAUDE / README / Architecture</b> נעם עורך, אור בודק</span><span><b>DECISIONS</b> אור מספק רציונל, נעם משלב</span><span><b>דוח ומצגת</b> עורך אחד בכל גרסה</span></div>
          </div>
        </div>
      </section>

      <section className="section shell" id="roadmap">
        <div className="roadmap-head">
          <div className="section-heading">
            <p className="eyebrow dark">Backlog בשלבים</p>
            <h2>מסננים לפי בעל אחריות.</h2>
            <p>המסנן אינו משנה את התוכנית — הוא פשוט מציג לכל אחד את המסלול שלו בלי לאבד את נקודות החיבור.</p>
          </div>
          <div className="filters" role="group" aria-label="סינון משימות לפי בעלים">
            {([['all','הכול'],['or','אור'],['noam','נעם'],['joint','משותף']] as const).map(([value,label]) => <button key={value} type="button" className={owner === value ? 'active' : ''} onClick={() => setOwner(value)}>{label}</button>)}
          </div>
        </div>
        <div className="roadmap-list" aria-live="polite">
          {visibleTasks.map((task) => <article key={task.id} className={`roadmap-item owner-${task.owner}`}><div className="phase-number"><small>שלב</small><b>{task.phase}</b></div><div className="task-body"><div className="task-meta"><span>{task.id}</span><span>{ownerLabel[task.owner as Exclude<Owner,'all'>]}</span></div><h3>{task.title}</h3><p>{task.detail}</p><footer><b>שער מעבר:</b> {task.gate}</footer></div></article>)}
        </div>
      </section>

      <section className="section handoff-section" id="handoff">
        <div className="shell">
          <div className="section-heading">
            <p className="eyebrow dark">חוזה מסירה</p>
            <h2>כל התקפה עוברת מיד ליד פעם אחת.</h2>
          </div>
          <div className="handoff-grid">
            <article><header><span>01</span><h3>אור מוסר חבילת התקפה</h3></header><ol><li>Threat ID + catalog ID</li><li>Scenario YAML</li><li>Canary או fake secret</li><li>קריטריון הצלחה ללא הגנה</li><li>pytest עם Fake backend</li><li>Tool/session events</li><li>נקודת mitigation צפויה</li></ol></article>
            <div className="handoff-arrow" aria-hidden="true">←</div>
            <article><header><span>02</span><h3>נעם מחזיר חבילת הגנה</h3></header><ol><li>Detector + verdict</li><li>Mitigation</li><li>בדיקת זיהוי או חסימה</li><li>Benign tests + FPR</li><li>Latency</li><li>הסבר trace לכל פספוס</li></ol></article>
          </div>
        </div>
      </section>

      <section className="section shell" id="quality">
        <div className="section-heading"><p className="eyebrow dark">שערי איכות</p><h2>לא מתקדמים על בסיס “נראה שעובד”.</h2></div>
        <div className="gate-grid">
          <article><span>G1</span><h3>שער Foundation</h3><p><code>uv sync</code> עובד; הדמו הקיים נשמר; אין בדיקות CI שקוראות ל־Gemini.</p></article>
          <article><span>G2</span><h3>שער Green Pipeline</h3><p>Smoke scenario דטרמיניסטי כותב events ו־metrics; כל ארבעת כלי האיכות ירוקים.</p></article>
          <article><span>G3</span><h3>שער Attack</h3><p>לכל וריאציה יש DECISION, YAML, canary ובדיקת הצלחה במצב <code>none</code>.</p></article>
          <article><span>G4</span><h3>שער Defense</h3><p>יש verdict מוסבר, חסימה או redaction, בדיקות benign ומדידת latency.</p></article>
          <article><span>G5</span><h3>שער מסירה</h3><p>כל מספר בדוח נובע מ־artifact; כל טענת מצגת ניתנת למעקב לקוד, ריצה או מקור.</p></article>
        </div>
        <div className="risk-grid">
          <div><b>Backend אמיתי</b><p>להשאיר Gemini כי הוא כבר עובד; לבנות Fake ראשון. Anthropic/Ollama רק אם המנחה דורשת.</p></div>
          <div><b>סודות ולוגים</b><p>אין להדפיס תוצאות כלי מלאות. כל canary פיקטיבי עובר sanitization לפני stdout או events.</p></div>
          <div><b>Session attacks</b><p>אי אפשר לממש נכון לפני session מתמשך, user_id מפורש ו־nonce/sequence.</p></div>
          <div><b>תמונות</b><p>נשארות ב־future work עד ששש וריאציות הליבה וכל המדדים ניתנים לשחזור.</p></div>
        </div>
      </section>

      <section className="section cadence-section">
        <div className="shell cadence-grid">
          <div><p className="eyebrow">קצב עבודה</p><h2>סנכרון קצר, אינטגרציה קבועה.</h2></div>
          <div className="cadence-list"><p><b>תחילת שבוע · 20 דק׳</b><span>בוחרים backlog ומוודאים שאין חפיפת paths.</span></p><p><b>עדכון יומי · 4 שורות</b><span>done / next / blocked / files touched.</span></p><p><b>אמצע שבוע · 30 דק׳</b><span>ממזגים PRs ומריצים את כל השערים.</span></p><p><b>סוף שבוע · 45 דק׳</b><span>מריצים suite, מעדכנים session note ומצגת בעובדות מאומתות בלבד.</span></p></div>
        </div>
      </section>

      <section className="section start-section" id="start">
        <div className="shell start-grid">
          <div>
            <p className="eyebrow dark">מה עושים עכשיו</p>
            <h2>חמש פעולות לפני שורת הקוד הבאה.</h2>
            <p>סמנו יחד. ההתקדמות נשמרת רק כל עוד הדף פתוח — זו רשימת תיאום, לא מערכת ניהול משימות.</p>
            <div className="progress" aria-label={`${doneCount} מתוך 5 הושלמו`}><span style={{width: `${doneCount * 20}%`}} /></div>
            <small>{doneCount}/5 הושלמו</small>
          </div>
          <div className="checklist">
            {[
              'מאשרים את שש וריאציות הליבה ואת הדדליין האמיתי.',
              'מתעדים Gemini כ־backend אמיתי ו־Fake כ־backend של הבדיקות.',
              'מחליטים על user_id, session_id, nonce/sequence ועל פורמט canary.',
              'פותחים Issues לפי מזהי ה־backlog ומפעילים הגנה על main.',
              'אור פותח or/foundation-migration; נעם מתחיל experiment-plan ו־defense-catalog.',
            ].map((item, i) => <label key={item} className={checked[i] ? 'checked' : ''}><input type="checkbox" checked={checked[i]} onChange={() => setChecked((current) => current.map((value, index) => index === i ? !value : value))} /><span aria-hidden="true">{checked[i] ? '✓' : ''}</span><b>{item}</b></label>)}
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="shell"><div className="brand"><span className="brand-mark">M</span><span><b>MCP Attack &amp; Defense Simulator</b><small>תוכנית עבודה משותפת · נעם ואור</small></span></div><p>מבוסס על אודיט מלא של המאגר ומסמכי הפרויקט · 24 באוגוסט 2026</p><a href="#top">חזרה למעלה ↑</a></div>
      </footer>
    </main>
  );
}
