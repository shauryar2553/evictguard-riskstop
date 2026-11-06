"""Build the viva explainer (Word) from the project's actual result files.

Usage: .venv_mac/bin/python scripts/make_viva_doc.py [output.docx]
Re-run after the OOD benchmark finishes; the results table fills itself in.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "Desktop" / "EVICTGuard_Viva_Guide.docx"

doc = Document()
style = doc.styles["Normal"]
style.font.name = "Calibri"
style.font.size = Pt(11)


def h(text, level=1):
    doc.add_heading(text, level=level)


def p(text, bold_prefix=None, italic=False):
    para = doc.add_paragraph()
    if bold_prefix:
        para.add_run(bold_prefix).bold = True
    run = para.add_run(text)
    run.italic = italic
    return para


def bullets(items, style_name="List Bullet"):
    for item in items:
        para = doc.add_paragraph(style=style_name)
        if isinstance(item, tuple):
            para.add_run(item[0]).bold = True
            para.add_run(item[1])
        else:
            para.add_run(item)


def box(text):
    para = doc.add_paragraph()
    run = para.add_run("In simple words: ")
    run.bold = True
    run.font.color.rgb = RGBColor(0x1F, 0x4E, 0x79)
    r2 = para.add_run(text)
    r2.italic = True
    return para


def table(rows, header):
    t = doc.add_table(rows=1, cols=len(header))
    t.style = "Light Grid Accent 1"
    for i, col in enumerate(header):
        cell = t.rows[0].cells[i]
        cell.text = ""
        cell.paragraphs[0].add_run(str(col)).bold = True
    for row in rows:
        cells = t.add_row().cells
        for i, value in enumerate(row):
            cells[i].text = str(value)
    doc.add_paragraph()


def qa(q, a):
    para = doc.add_paragraph()
    para.add_run("Q: " + q).bold = True
    doc.add_paragraph("A: " + a)


# ------------------------------------------------------------------ title
title = doc.add_heading("EVICTGuard + RISKSTOP: What We Built and Why", 0)
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
p("A step-by-step, plain-language guide to the dataset, labelling, and evaluation pipeline, written for viva preparation.", italic=True)

# ------------------------------------------------------------------ 0
h("0. The whole story in 60 seconds")
p("Our project builds two parts for an AI (LLM) assistant that investigates security alerts in a Security Operations Centre (SOC):")
bullets([
    ("EVICTGuard: ", "decides which log events to keep when the AI's memory (context window) is full, so that important attack evidence is not thrown away when attackers flood the logs with junk."),
    ("RISKSTOP: ", "decides when the investigation should stop and say ATTACK, BENIGN, or DEFER (hand over to a human)."),
])
p("To test whether these work, we need data where we already know the right answer: which events are attack events and which are normal. Our original dataset had no such answers (labels). So we:")
bullets([
    "researched about 15 public security datasets and chose a combination (OTRF + ATLASv2);",
    "built a program that automatically labels every log event (Sigma detection rules + process-tree tracing), checked a sample, and fixed the problems the check found;",
    "built 300+ practice investigations (\"episodes\") with fair train/validation/test splits;",
    "added noise (floods, duplicates, fake look-alikes, deleted evidence) without losing the answers;",
    "measured how much attack evidence EVICTGuard keeps compared with simple baselines (FIFO, Random);",
    "found an important weakness: spliced (artificially combined) data made the original EVICTGuard (v1) look far better than it was; on real attacks it was near random.",
    "redesigned EVICTGuard (v2, then v3 and a streaming Online v2) with seven label-free security signals, froze each version before testing, and tested on three datasets against baselines from our literature review.",
], "List Number")
h("Final scoreboard (held-out data only)", 2)
table([
    ["ATLASv2 real attacks (expert labels), keep 0.5% of the log", "0.97", "0.05 (rare-action)", "0.00", "6/6 attacks, p = 0.031"],
    ["ATLASv2, keep only 0.13% of the log (256 events)", "0.96–0.97 (Online v2 / v3)", "0.01", "—", "v2 was 0.79 here"],
    ["OTRF native attacks (Windows 10, our labels), keep 1%", "0.53 (Online v2)", "0.07–0.11", "0.19", "fresh validation split"],
    ["OTRF native attacks, keep 5%", "0.87–0.90", "0.33–0.38", "0.33–0.67", "batch v2 significant vs all except v1"],
    ["CDB campaign (someone else's labels, Azure-agent flags excluded), keep 5%", "0.14–0.17", "0.27 (rare-action)", "0.13", "EVICTGuard NOT better here (limitation); raw labels: all methods ≤ 0.12"],
], ["Test", "EVICTGuard (best version)", "Best literature baseline", "Old v1", "Note"])
box("Where 'evidence' means what the attacker actually did (expert labels), EVICTGuard keeps nearly everything in a tiny memory and every baseline keeps almost nothing. Under CDB's broad automatic labels it is only on par with a simple baseline, and we say so.")

# ------------------------------------------------------------------ 1
h("1. Where we started (the problem)")
p("The first version of the code (Phases 1–3) used one OTRF recording: an \"Empire DCOM ShellWindows\" attack. It had:")
bullets([
    "32,706 log events covering only about 2 minutes, from 4 computers;",
    "no labels: nothing said which events were the attack;",
    "only 1 attack and 0 normal (benign) investigations.",
])
p("Because of this, the most important result, \"how much critical attack evidence does EVICTGuard keep?\", was always empty (null) in every results file. We also noticed that EVICTGuard kept 76 of 250 fake noise events (Random kept 25), because the noise had a unique event type and EVICTGuard rewards rare things. Without labels we couldn't even tell whether this was good or bad.")
box("You can't grade an exam without an answer key. Our data had no answer key, so we had to build one.")

# ------------------------------------------------------------------ 2
h("2. Choosing the dataset")
h("2.1 What a dataset must give us", 2)
table([
    ["Event-level labels", "Which exact log lines are attack evidence", "Needed to measure EVICTGuard"],
    ["Episode labels incl. BENIGN", "Whole investigations marked attack / normal", "Needed to measure RISKSTOP and false alarms"],
    ["Many episodes", "Hundreds, not one", "Needed for train/validation/test splits"],
    ["ATT&CK mapping", "Which attack technique each attack uses", "For attack-stage features and fair splits"],
    ["Multiple log sources and hosts", "Sysmon, Security, PowerShell; several computers", "For diversity and corroboration features"],
    ["Free and downloadable", "No emailing, laptop-friendly", "Practical constraint"],
], ["Requirement", "Meaning", "Why we need it"])

h("2.2 What we found", 2)
bullets([
    ("Cyber Defense Benchmark (CDB), Chona et al. 2026: ", "was planned as our primary dataset. Problem: the full benchmark is only shared with organisations on request (only one sample is public), it's built from the same OTRF recordings anyway, and it has no real benign data (only 500 synthetic events per campaign). So it can't be our main dataset. We do borrow its labelling idea."),
    ("OTRF Security-Datasets (Mordor): ", "about 100 free Windows attack recordings, each mapped to an ATT&CK technique. Problem: no event-level labels and no benign recordings. Good as an attack pool if we create the labels ourselves."),
    ("ATLASv2 (Riddle et al. 2023): ", "4 days of real, human-generated normal Windows activity plus 10 attacks with expert ground truth (REAPr labels and ATLAS's own list of malicious events). Its README says \"We encourage you to use the ATLASv2 dataset in your experiments\", so citing it is enough and no email is needed. Problem: 160 GB uncompressed, Windows 7 only."),
    ("Others rejected: ", "DARPA OpTC/TC (huge, labels only in PDFs), LANL (mostly authentication logs), Splunk BOTS (quiz answers, not event labels), CICIDS/UNSW (network-only), AIT (Linux)."),
])
h("2.3 Final choice: a hybrid", 2)
table([
    ["Attack pool", "OTRF: 110 Windows recordings (about 1.5M events)", "Labels built by us (Section 4)"],
    ["Normal background", "ATLASv2 benign period: 5 days, 458,389 events after removing duplicates", "Benign by design of the dataset"],
    ["Realistic test (out-of-distribution)", "All 16 ATLASv2 attack scenarios, real attacks in real background", "ATLAS ground truth (core) + REAPr (supporting)"],
], ["Role", "Source", "Labels"])
box("OTRF gives us many different attacks. ATLASv2 gives us real normal activity and a few real attacks that nobody artificially mixed together.")

# ------------------------------------------------------------------ 3
h("3. Getting the data (keeping RAM and storage small)")
bullets([
    ("OTRF: ", "src/otrf_corpus.py downloads every Windows host recording plus its metadata file (ATT&CK technique, tools used, attacker's console output). That's 110 recordings, about 115 MB. One link was broken (404) and is skipped and logged."),
    ("ATLASv2 problem: ", "Box only offers one 12.2 GB compressed file, so you can't download single folders."),
    ("Our solution, streaming: ", "src/atlas_adapter.py reads the 12 GB file over the internet once, converts only the files we need straight into compact tables, never saves the raw XML, and stops as soon as it has what it needs. Result: about 233 MB kept, under 1 GB RAM. It survived several internet drops by resuming from the exact byte where it stopped (HTTP Range requests)."),
    ("Hidden trap we caught: ", "ATLASv2's Sysmon files are cumulative. The day-5 file also contains days 1–4, so the same events appeared in up to 5 files, which would leak identical data into train and test. We removed duplicates (570,742 → 458,389 events) and re-cut the data into one segment per calendar day."),
])

# ------------------------------------------------------------------ 4
h("4. Building the answer key: event-level labelling")
p("File: src/label.py (+ src/sigma_engine.py). This follows the same idea as CDB (Sigma rules + causal neighbours) and REAPr (process-tree tracing), but uses no AI model, so the labels are deterministic and reproducible.")
h("4.1 The four steps", 2)
bullets([
    ("Step 1, find where the attack starts (roots). ", "(a) OTRF metadata contains the attacker's own console output, which names the attacker's process and PID (e.g. powershell.exe PID 5904 on WORKSTATION5). We match these to log events. (b) High-severity Sigma rule hits on process-creation events."),
    ("Step 2, follow the family tree. ", "Every Windows process has an ID (ProcessGuid) and a parent ID. Starting from the roots we follow parent → child links. Everything the attacker's processes started is part of the attack tree. PowerShell and Security events without IDs are matched by computer + process number."),
    ("Step 3, assign tiers. ", "core = a Sigma rule fired inside the attack tree, or fired outside it but matches the recording's documented ATT&CK technique. supporting = done by an attacker process with no rule firing (context). ambiguous = a rule fired outside the tree and doesn't match the technique, so it's excluded from scoring. background = everything else."),
    ("Step 4, record provenance. ", "Every label stores why it was given (which rule, which root), so anyone can check it."),
], "List Number")
box("Sigma rules are like a list of known suspicious behaviours. The process tree tells us who did what. An event counts as attack evidence when it's both suspicious and done by the attacker (or clearly matches the attack technique).")

h("4.2 Our Sigma rule engine", 2)
p("Sigma is an open standard for detection rules (SigmaHQ has about 2,400 Windows rules). Instead of a heavy external tool, we wrote a small, readable evaluator that supports the common rule features (contains, startswith, endswith, regex, windash, IP ranges, conditions like '1 of selection_*'). Rules using features we don't support are skipped and counted, never guessed. 2,339 rules are evaluable. It processes 32,706 events in about 5 seconds.")

h("4.3 Checking the labels and fixing what we found (important for the viva)", 2)
p("We reviewed a stratified sample (30 core, 30 supporting, 25 ambiguous, 15 background). This first review was model-assisted, not human. It found three real problems:")
table([
    ["\"Any high-severity hit = attack\" rule", "Lab housekeeping (Security log cleared, file shredding) was labelled attack: 7 of 30 core events wrong", "High-severity hits outside the attack tree now need a technique match"],
    ["\"Attacker process is the target\" counted", "Normal Windows processes (csrss, svchost) opening an attacker process were labelled attack", "Only the acting process counts"],
    ["Newest Sigma uses renumbered ATT&CK IDs", "T1562.004 became T1686.003, so technique matching silently failed and real attacks (net1 user /add backdoor, PsExec) were left ambiguous", "Pinned Sigma to release r2026-04-01, which uses the same IDs as OTRF"],
], ["Problem", "Effect", "Fix"])
p("After the fixes, a re-check of 30 new core samples found all 30 to be real attack activity (before: 19 of 30). Technique agreement rose from 63 to 72 of the 84 labelled recordings.")
h("4.4 Final label numbers", 2)
table([
    ["Recordings downloaded", "110"],
    ["Recordings with trustworthy core evidence (used)", "84"],
    ["Total events labelled", "1,535,364"],
    ["core / supporting / ambiguous", "3,380 / 123,345 / 6,150"],
    ["Recordings where attacker console processes were found", "31"],
], ["Item", "Value"])
p("Still to do: a human fills the 'reviewer_is_attack' column (yes / no / unsure) in the 60-row sheet on the Desktop (EVICTGuard_label_review.csv), then runs python -m scripts.label_review_kit score. This gives the official agreement and Cohen's kappa.")

# ------------------------------------------------------------------ 5
h("5. Building investigations (episodes)")
p("File: src/compose_episodes.py.")
bullets([
    ("ATTACK episode: ", "a slice of normal activity (up to 4,000 events) with 1–3 OTRF attacks inserted. The attack's timestamps are shifted into the slice and its computer names are replaced with the background's computer name, both in the tidy columns and inside the raw log JSON."),
    ("BENIGN episode: ", "a slice of normal activity only."),
    ("Counts: ", "train 120 attack / 60 benign; validation 40 / 20; test 40 / 20; plus 16 real ATLASv2 attack episodes (the 'ood' split)."),
    ("No cheating (leakage) between splits: ", "attacks are grouped by ATT&CK technique family. A whole family goes to one split (50 / 17 / 17 recordings), so the test set contains techniques never seen in training. Normal background is split by calendar day."),
    ("Sensor harmonisation: ", "only attack event types that the background's logging also produces are inserted (explained in Section 8)."),
    ("Memory: ", "data is read one block at a time, which cut peak RAM from 8.7 GB to about 3.6 GB."),
])

# ------------------------------------------------------------------ 6
h("6. Noise and augmentation (labels are never lost)")
p("File: src/noise.py. Every injected event is marked benign by construction, and every removed event is recorded.")
table([
    ["duplicate-flooding", "Exact copies of events", "Copy inherits its parent's label and links to it (dup_of)"],
    ["background-flood", "Replays real normal events with new times", "benign / injected_noise"],
    ["mimic-flood", "Normal admin commands that look like hacking (whoami, net user, schtasks /query)", "benign / injected_noise: tests adversarial look-alikes"],
    ["missing-evidence", "Deletes random events", "Records which deleted events were attack evidence"],
    ["missing-critical", "Deletes a share of the attack evidence", "Used for the DEFER rule"],
], ["Type", "What it does", "Label handling"])

# ------------------------------------------------------------------ 7
h("7. The answer key for RISKSTOP (decided before any experiment)")
bullets([
    "BENIGN episode → correct answer is BENIGN.",
    "ATTACK episode with at least 50% of its core evidence still present (and at least 1 core event) → ATTACK.",
    "ATTACK episode with less than that → DEFER (not enough evidence; a human should look).",
])
box("We fixed the rule in advance so nobody can say we moved the goalposts after seeing results.")

# ------------------------------------------------------------------ 8
h("8. Results and what they mean")
p("Metric: core recall = out of all the attack evidence, how much ended up in the AI's limited memory. Higher is better. FIFO = keep the newest events; Random = keep a random sample. Numbers in brackets are 95% confidence intervals.")
h("8.1 Spliced episodes (validation split)", 2)
table([
    ["Interim: OTRF lab background", "0.39–0.51", "0.12–0.31", "0.03–0.17"],
    ["ATLASv2 background, no harmonisation", "0.76–0.81", "0.11–0.24", "0.02–0.14"],
    ["ATLASv2 background, harmonised", "0.93–1.00", "0.15–0.27", "0.00–0.22"],
], ["Setting", "EVICTGuard", "FIFO", "Random"])
h("8.2 The key discovery: these spliced numbers are inflated", 2)
p("We measured that 83% of attack events used a log event type that never appears in their background slice. OTRF attacks were recorded on Windows 10 with detailed Sysmon logging; ATLASv2 background is Windows 7, mostly Security logs. EVICTGuard's main feature rewards rare event types, so it spots the inserted attack events trivially. Harmonisation cut this to 9%, but the episodes stayed easy, and 17 of 40 validation attack episodes lost all their core events.")
box("It's like hiding a red ball among green balls and praising someone for finding it. The test was too easy, not the method too good.")

h("8.3 The realistic test: 16 real ATLASv2 attacks (no splicing)", 2)
ood_path = ROOT / "results" / "benchmark" / "summary_ood.csv"
ood_ok = False
if ood_path.exists():
    ood = pd.read_csv(ood_path)
    if ood.episodes.max() >= 16:
        ood_ok = True
        rows = []
        for (noise, cap), part in ood.groupby(["noise", "capacity"]):
            vals = {r.method: f"{r.core_recall:.3f}" for r in part.itertuples()}
            rows.append([noise, cap, vals.get("evictguard", ""), vals.get("fifo", ""), vals.get("random", "")])
        table(rows, ["Noise", "Capacity (events kept)", "EVICTGuard", "FIFO", "Random"])
        p("Each real episode has about 223,000 events and about 256 core attack events, so a capacity of 1,024 keeps under 0.5% of the log and 4,096 keeps about 1.8%. Random keeps attack evidence at roughly that chance rate (0.017 at 4,096). EVICTGuard (0.022) is only slightly above chance, and the confidence intervals nearly overlap. FIFO keeps almost nothing (0.0002), because the attack isn't at the end of the log.")
if not ood_ok:
    p("[Results pending: re-run scripts/make_viva_doc.py after the 16-episode benchmark finishes.] On the first real episode alone (h1-s1), EVICTGuard kept only 1.4–1.9% of core evidence, versus 0–0.3% for FIFO and 0–1.9% for Random.", italic=True)
p("Interpretation (this is the ORIGINAL EVICTGuard v1; section 11 shows the redesigned v2/v3, which keeps 0.97 here): on realistic data, v1's scoring (rarity of event type + same-host corroboration + not-a-duplicate) can't find attack events, because ATLAS's malicious Security events use the same common event types as normal activity. This is a finding about the scoring method, not a pipeline failure. The pipeline did its job by revealing it.")

# ------------------------------------------------------------------ 9
h("9. Every change we made to the code")
h("New files", 2)
table([
    ["src/otrf_corpus.py", "Downloads all OTRF Windows recordings + metadata and builds index.csv"],
    ["src/sigma_engine.py", "Small, transparent Sigma rule evaluator"],
    ["src/label.py", "Event-level labelling (roots → process tree → tiers), review sample, agreement"],
    ["src/compose_episodes.py", "Builds ATTACK/BENIGN/OOD episodes, leakage-safe splits, harmonisation, low-RAM loading"],
    ["src/atlas_adapter.py", "ATLASv2 streaming (resumable), XML parsing, de-duplication by day, REAPr + ATLAS ground truth"],
    ["src/run_benchmark.py", "EVICTGuard vs FIFO vs Random, recall metrics, bootstrap CIs, gold RISKSTOP verdicts; now also v2, ablations, action-level recall, AP"],
    ["src/evictguard_v2.py", "NEW scoring: prevalence, lineage, location, target location, sensitivity, informativeness, novelty, de-duplication"],
    ["tests/test_evictguard_v2.py", "Proves v2 never uses labels/noise markers; lineage, de-duplication, history"],
    ["scripts/make_paper_results.py", "Publication tables, figures, significance tests"],
    ["run_pipeline.sh", "Runs everything in order with one command"],
    ["tests/test_labelling_pipeline.py", "13 new tests (31 total, all passing)"],
    ["docs/DATASET.md", "Full technical description of the dataset design"],
], ["File", "Purpose"])
h("Changed files", 2)
table([
    ["src/noise.py", "Added background-flood, mimic-flood, missing-critical; duplicates inherit labels; injected events labelled benign"],
    ["src/utils.py", "Bug fix: ZIP loader was reading macOS junk files (__MACOSX/._*) instead of the data"],
    ["src/label.py (standardize)", "Bug fix: host names normalised (WORKSTATION6 and workstation6.theshire.local were counted as 2 hosts); hex process IDs (0x890) parsed"],
    ["requirements.txt", "Added pyyaml and pyarrow"],
], ["File", "Change"])
p("The original EVICTGuard scoring (src/selection.py) is kept unchanged as 'v1' for comparison. The new method is in src/evictguard_v2.py.")

# ------------------------------------------------------------------ 10
h("10. Where we stand right now")
table([
    ["Dataset choice", "Done", "ATLASv2 (expert labels) + OTRF native (our labels) + CDB public campaign (CDB's labels)"],
    ["Event-level labels", "Done; cross-checked against CDB (kappa 0.08–0.19)", "Human agreement check still to do (sheet ready)"],
    ["Episodes + splits + noise", "Done", "Leakage-safe; labels preserved"],
    ["EVICTGuard v1 evaluation", "Done", "Strong on spliced data, near random on real attacks"],
    ["EVICTGuard v2 (new scoring)", "Done: built, tested, frozen, evaluated", "Held-out: 0.973 recall at 0.5% of the log (v1 0.000, Random 0.015)"],
    ["EVICTGuard completion", "Done", "Second and third datasets, literature baselines, streaming version, robustness, ledger + context assembly"],
    ["Caveat fixes (v3, Online v2, coverage, tie-break seeds)", "Done", "Each frozen before its fresh test; results in 11.10"],
    ["End-to-end LLM verdict test", "Open", "Needs an LLM (API key or local model)"],
    ["RISKSTOP", "Built end to end (no LLM) with guaranteed error rates", "Real-alert benchmark: missed attacks 0–5% vs 16–36% for baselines, ~10% budget, lowest cost; see 11b"],
    ["EVICTGuard v4 + Carbon Black fresh test", "Done", "v4 no gain (negative result); EVICTGuard leads on a new sensor"],
], ["Part", "Status", "Notes"])
h("Honest limitations", 2)
bullets([
    "OTRF labels are rule-based plus process tracing, and agree only slightly with CDB's independent labeller; a human review is still needed.",
    "Spliced episodes are artificially easy (Windows 10 attacks in Windows 7 background); they're secondary results only.",
    "ATLASv2's 10 attacks are very similar to each other (shared steps), so the 16 real episodes are variations of a few attack chains.",
    "On CDB's broad automatic evidence definition, EVICTGuard only matches a simple rare-event baseline.",
])
h("Next steps", 2)
bullets([
    "Do the human label check (about 30 minutes) and report agreement.",
    "End-to-end test: an LLM investigator reads EVICTGuard's memory vs FIFO's; compare verdicts.",
    "Add the LLM investigator (API key) and re-run RISKSTOP end to end.",
    "Speed up Online v2 on very large streams (about 900k events).",
], "List Number")


# ------------------------------------------------------------------ 11b
h("11. NEW: EVICTGuard v2, the redesigned scoring method")
p("After the realistic test showed that the original EVICTGuard (v1) was barely better than random, we redesigned the scoring. This section explains what changed, why, how we kept it honest, and the final results.")
h("11.1 Why v1 failed", 2)
bullets([
    "v1 scored events on three generic statistics: how rare the event type is, how many different events the same computer has, and whether the event is an exact duplicate.",
    "In the real ATLASv2 attacks, the attacker's events use the same common event types as normal activity (e.g. 'file accessed'), so event-type rarity can't find them.",
    "The proposal (slide 14) promised signals such as sensitivity, attack stage and relevance; v1 didn't implement them.",
])
h("11.2 What we looked at (development data only)", 2)
p("We studied only the 10 host-1 attacks (h1-*) to understand what real attack evidence looks like:")
bullets([
    "The attacker's program (payload.exe) produced about 48,000 events, but only about 260 are attack evidence.",
    "Those 260 are its first actions on distinct objects in user-writable places: its own unpacked folder in Temp and the user's home folder. Its thousands of reads of Windows system library files (winsxs, assembly) are normal program loading.",
    "The program itself is unusual: it runs from a user's folder, was never seen on that machine before, and was started through a chain like browser, then plugin, then cmd.exe, then payload.exe.",
])
h("11.3 The new scoring: seven signals, each based on established security practice", 2)
table([
    ["Historical prevalence", "Programs, actions and objects never seen in the organisation's past normal logs are suspicious", "NoDoze (Hassan et al., NDSS 2019): our literature survey, slide 5"],
    ["Process lineage", "Suspicion flows from parent to child process; a browser or Office spawning a shell is anomalous", "Provenance analysis / REAPr"],
    ["Location risk", "Programs running from user-writable folders (Downloads, AppData, Temp)", "MITRE ATT&CK T1204, T1036"],
    ["Target-location risk", "Actions on user-writable objects (staging, collection) matter; reads of OS libraries don't", "ATT&CK T1074, T1005, T1105"],
    ["Target sensitivity", "Credential stores, persistence keys, security logs", "Slide 14 'sensitivity'"],
    ["Action informativeness", "'File accessed' or 'process created' says more than 'handle closed'", "Windows audit / Sysmon semantics"],
    ["Novelty + de-duplication", "The first time a process touches an object counts; identical repeats are collapsed", "Slide 14 'redundancy'"],
], ["Signal", "Idea", "Where it comes from"])
p("These combine into one evidence value per event. EVICTGuard then keeps the highest-value evidence, plus a 10% 'exploration reserve' spread across computers and event types (slide 15).")
box("v1 asked 'is this kind of event rare?'. v2 asks 'is this done by a suspicious program, is it new, and does it touch something that matters?'")
h("11.4 How we kept it honest (important for reviewers and the viva)", 2)
bullets([
    ("No labels: ", "the scorer never reads the answer key or any 'this is injected noise' marker. An automated test proves that changing those columns changes nothing. (v1 actually did use the 'synthetic' flag, which a real system wouldn't have.)"),
    ("History from the past only: ", "the 'never seen before' profile is built only from the training days of normal activity."),
    ("Development vs held-out: ", "all design decisions used only the 10 host-1 attacks. The 6 host-2 attacks were never looked at. The design was then frozen, and its fingerprint (SHA-256 b118c8a5…) is saved, so anyone can verify that the held-out results come from the frozen code."),
    ("Two recall measures: ", "record-level (the exact log line ATLAS marked) and action-level (the same action by the same process on the same object, logged several times). We report both, for every method."),
    ("Ablation: ", "each signal is removed one at a time to show what it contributes."),
    ("Statistics: ", "95% bootstrap confidence intervals and exact paired permutation tests over episodes."),
])
h("11.5 FINAL RESULTS: the 6 held-out real attacks (never used for design)", 2)
p("Measure: core attack-evidence recall = out of all the real attack evidence, how much EVICTGuard kept in the AI's limited memory. Numbers in brackets are 95% confidence intervals.")
table([
    ["256 events (0.13% of the log)", "0.790 [0.594–0.893]", "—", "0.004", "0.000"],
    ["1,024 events (0.51% of the log)", "0.973 [0.960–0.982]", "0.000", "0.015", "0.000"],
    ["4,096 events (2.0% of the log)", "0.985 [0.972–0.994]", "0.023", "0.031", "0.000"],
], ["Memory size", "EVICTGuard v2 (ours)", "EVICTGuard v1 (old)", "Random", "FIFO"])
bullets([
    ("In one sentence: ", "keeping only half a percent of the log, v2 keeps 97% of the real attack evidence; the old version kept 0%, random kept 1.5%."),
    ("Every attack, not just on average: ", "v2 beat every baseline on all 6 held-out attacks and all 10 development attacks. Statistical test: p = 0.031 held-out (the smallest possible with 6 attacks) and p = 0.002 on development."),
    ("Strict per-record measure: ", "0.507 for v2 vs 0.000 (v1) and 0.007 (Random) at 1,024 events. This is lower because ATLAS marks one specific copy of actions that are logged several times; v2 keeps one copy of each action."),
    ("Ranking quality (average precision): ", "0.377 for v2, against about 0.001 for a random ranking."),
])
h("11.6 Under attack-style flooding (held-out, 1,024 events)", 2)
table([
    ["Duplicate flood (+50%)", "0.973", "0.000", "0.303", "0.339"],
    ["Background flood (+50%)", "0.973", "0.025", "0.303", "0.636"],
    ["Mimic flood (+20%, fake 'hacker-looking' commands)", "0.973", "0.022", "0.160", "0.327"],
], ["Noise", "v2 recall", "v2: share of memory wasted on junk", "Random: junk share", "FIFO: junk share"])
p("v2's recall doesn't move under any flood, and it lets almost no junk into memory. FIFO fills up to 64% of its memory with junk.")
h("11.7 Which signals matter (ablation, development data)", 2)
table([
    ["Event-type informativeness", "−0.245"], ["Target-location risk", "−0.240"], ["Historical profile (history)", "−0.029"],
    ["Prevalence", "−0.021"], ["Location risk", "−0.010"], ["Lineage", "−0.010"], ["LOLBin", "−0.007"], ["Sensitivity", "−0.003"],
    ["Propagation / command", "≈0"], ["Novelty", "+0.008 (slightly better without it)"], ["De-duplication weighting", "+0.031 (slightly better without it)"],
], ["Signal removed", "Change in recall"])
p("Two signals turned out slightly harmful. We kept them in the frozen design on purpose: changing the design after seeing held-out results would be cheating (test-set tuning). They are reported as findings.")
h("11.8 Spliced episodes (secondary)", 2)
p("On the artificially combined OTRF-into-ATLASv2 episodes, both v1 and v2 score about 1.0 (FIFO 0.08–0.31, Random 0.01–0.17). This confirms these episodes are too easy to separate methods (the Windows 10 vs Windows 7 artefact). One honest detail: under background flooding there, v2's memory held 31–35% junk versus 14–19% for v1.")
h("11.9 Finishing EVICTGuard: second dataset, literature baselines, streaming, robustness", 2)
p("To finish EVICTGuard properly, we added four things reviewers expect.")
bullets([
    ("A second, independent dataset: ", "84 native OTRF attacks (Windows 10, a different lab, real background, no splicing). The frozen v2 had never seen them and ran with no history (cold start). On the 17 test attacks, keeping 1% / 5% of events: v2 0.58 / 0.87 vs old v1 0.19 / 0.67, rare-action 0.07 / 0.34, NoDoze-style 0.04 / 0.28, Random 0.02, FIFO 0.00. It beat every baseline significantly, except v1 at 5% (p = 0.087), where many small episodes tie."),
    ("Baselines from our literature review, rebuilt on our data: ", "NoDoze-style provenance triage (slide 5), Sigma alert prioritisation (AlertPro-style SOC practice), rare-action anomaly, and recency + de-duplication. On the 6 held-out ATLASv2 attacks at 0.5% of the log: v2 0.973 vs rare-action 0.048, NoDoze 0.006, Sigma 0.000, recency 0.000. v2 won on 6/6 attacks against each of them."),
    ("Why the baselines fail: ", "recency keeps the newest events (the attack was earlier); Sigma rules don't fire on the attacker's file activity but do fire on the security agent; the anomaly methods flag every action of every new program, so the attack ties with thousands of other 'new' events. v2 separates them using where the action lands and how informative it is."),
    ("A fairness fix we made: ", "the anomaly baselines first broke those ties by time, which made them score exactly 0. We switched to random tie-breaking so the comparison is fair. They now score a little above 0, still far below v2."),
    ("Streaming (online) EVICTGuard with the slide-15 reservoirs: ", "decides event by event using only the past, with a fixed memory split into protected, entity-coverage and exploration reservoirs. Held-out: ATLASv2 0.96 (256 events) / 0.97 (1,024), better than batch at small memory; OTRF 0.48 / 0.80, a bit below batch. Honest finding: the reservoirs don't change recall measurably; they exist for coverage and diversity."),
    ("Weights don't matter much: ", "changing all 9 weights randomly by up to ±50% (30 trials) kept recall at 0.82 ± 0.01 (worst 0.78). The result isn't tuned to lucky numbers."),
    ("Engineering: ", "v2 now writes its protected/redundant/evicted decisions to the evidence ledger (evaluate.py --method v2), and src/context.py builds an LLM-ready context grouped by process, with pointers back to the raw evidence (slide 15 'context assembly')."),
])
box("Across two different environments, against every baseline we could build from our literature review, EVICTGuard keeps most of the attack evidence in a tiny memory, and the others keep almost none.")

h("11.10 Fixing the caveats (second round)", 2)
p("After the first full results, we listed every weakness and tried to fix each one properly, without tuning on test data.")
table([
    ["Baseline tie-break could be 'lucky'", "Re-ran with 5 random seeds", "Closed: numbers barely move (e.g. 0.047 ± 0.019)"],
    ["Streaming version weaker on OTRF", "Online v2: reservoirs only once memory is big enough; re-scores memory as it learns", "Fixed on fresh data: 0.53 vs 0.36 (old online) and 0.30 (batch) at 1%"],
    ["Reservoirs didn't raise recall", "Measured what they're for: coverage", "Justified: same recall, evidence variety 0.10 → 0.91"],
    ["Two signals slightly harmful", "v3 = v2 without redundancy weighting, tested fresh", "Mixed: much better on ATLASv2 (0.97 vs 0.79 at 256 events), mixed on OTRF"],
    ["Our own labels", "Third dataset with someone else's labels (CDB) + agreement check + human sheet", "Partly closed, important findings below"],
    ["OTRF training split missing", "Ran it", "Closed: v2/v3 0.40–0.77 vs best baseline 0.13–0.39"],
    ["End-to-end LLM test", "Needs an LLM (API key or local model)", "Open: your decision"],
], ["Weakness", "What we did", "Result"])
h("11.11 The third dataset (CDB): what we learned", 2)
bullets([
    ("What it is: ", "the public sample of the Cyber Defense Benchmark (our original slide-11 dataset): one 155,350-event attack campaign, labelled by its authors, not by us."),
    ("We found and fixed a bug in our own conversion: ", "CDB's real clock is the TimeCreated field. Our reader had used a different time field, which scrambled the event order. After the fix, all 3,393 flagged timestamps match."),
    ("We found a problem in CDB's labels: ", "70% of its 'core attack' timestamps are just the Azure cloud agent collecting logs. The same agent does the same thing in 4 unrelated attacks, so these are almost certainly false alarms in CDB's automatic labelling. We report results both with and without them."),
    ("Honest result: ", "on CDB, EVICTGuard is about as good as the simple 'rare action' baseline when memory is small, and behind it at 5%. CDB counts many side effects (like DLL loads) as core evidence, which EVICTGuard deliberately ranks low."),
    ("Labels disagree: ", "our labeller and CDB's labeller agree only slightly (Cohen's kappa 0.08–0.19). Automatic security labels are uncertain whoever makes them. That's why ATLASv2's expert labels are our strongest evidence, and why the human check matters."),
])
box("EVICTGuard is far better than every baseline when 'evidence' means what the attacker actually did (expert labels). It isn't better when 'evidence' is defined broadly by an automatic labeller. We say this openly; it's a limitation and future work, not something we hide.")

h("11.12 Honest limitations (what a journal reviewer will raise)", 2)
bullets([
    "The 6 held-out attacks are the second-computer halves of multi-host campaigns whose first halves were development data, so they're independent by computer and records, not by attack chain. ATLASv2's 10 attacks also share most steps.",
    "Second-dataset labels (OTRF) come from our own labeller; it agrees only slightly with CDB's independent labeller (kappa 0.08–0.19). A human check (sheet on the Desktop) is still to do.",
    "On CDB's broad automatic evidence definition, EVICTGuard is not better than simple rare-action ranking.",
    "Online v2 is slow on very large streams (about 900k events) because it re-scores its memory often; that's a performance issue to optimise.",
    "The target-location signal was added after studying development data. It's a standard ATT&CK-based idea, but it fits this attacker's behaviour closely.",
    "Baselines are faithful re-implementations of the core ideas (NoDoze, alert prioritisation), not the original systems. There's no end-to-end test yet of whether the LLM investigator reaches the right verdict with v2's memory; that comes with RISKSTOP.",
    "The flooding is synthetic, and v1 was compared only without noise (it's too slow).",
])
box("EVICTGuard is complete: tested on two environments, against literature baselines, in batch and streaming form, with robustness and ablation evidence. The remaining step for a full paper is the end-to-end LLM + RISKSTOP evaluation.")
p("Full tables, LaTeX, figures and significance tests: results/paper/. Write-up: docs/RESULTS_EVICTGUARD_V2.md.", italic=True)

h("11b. Optimisations and RISKSTOP (latest round)")
h("Faster streaming EVICTGuard", 2)
p("The streaming version is now 2–2.5× faster and makes exactly the same decisions. We checked this on 8 episodes, and a permanent test enforces it.")
h("EVICTGuard v4: an idea that didn't pan out", 2)
bullets([
    ("Idea: ", "reserve part of the memory for side effects (DLL loads, registry and file changes) of suspicious processes, because v2/v3 keep almost none of this supporting context."),
    ("Development result: ", "a small gain (OTRF supporting evidence 0.34 → 0.44)."),
    ("Fresh-data result: ", "no gain (0.09 vs 0.08 on Carbon Black). We report it as a negative result; v3 stays the best version."),
])
h("A brand-new sensor: Carbon Black EDR", 2)
p("To test on data no method had ever seen, we streamed ATLASv2's Carbon Black EDR telemetry (16 attacks) and joined it exactly to the REAPr expert process labels.")
table([
    ["EVICTGuard v3", "0.65", "0.87"], ["EVICTGuard v2", "0.65", "0.85"], ["Random", "0.50", "0.74"], ["Old v1", "0.49", "0.74"],
    ["Rare-action", "0.47", "0.59"], ["FIFO", "0.07", "0.36"], ["NoDoze-style", "0.12", "0.12"],
], ["Method", "Attack processes covered, keep 1%", "Keep 5%"])
p("EVICTGuard works on a sensor it was never designed on and leads. The margin over random is smaller here because REAPr's attack processes include common ones like explorer.exe.")
h("RISKSTOP: built end to end (without an LLM)", 2)
bullets([
    ("What it is: ", "at every step of an investigation it reads the evidence memory and decides CONTINUE, ATTACK, BENIGN or DEFER, and writes a decision certificate (verdict, reasons, cited evidence, open questions, budget used)."),
    ("How it was built: ", "a query layer with costs, a rule-based investigator standing in for the LLM, EVICTGuard memory, 18 label-free state features, two models trained on training data only, and thresholds calibrated on validation under error budgets (≤ 5% false alarms, ≤ 5% missed attacks)."),
    ("Tested against: ", "fixed budget, confidence stop, BAGEN-style 'stop when evidence stalls', and conformal deferral at the end (both ideas from our literature survey)."),
])
table([
    ["RISKSTOP (EVICTGuard memory)", "0.73", "0.00", "15%", "100%"],
    ["Stop when evidence stalls (BAGEN-style)", "0.77", "0.00", "22%", "100%"],
    ["Fixed budget (EVICTGuard memory)", "0.69", "0.25", "99%", "100%"],
    ["Fixed budget (FIFO memory)", "0.58", "0.62", "99%", "11%"],
], ["ATLASv2 test (reliable labels)", "Accuracy", "False alarms", "Budget used", "ATTACK verdicts citing real evidence"])
bullets([
    ("Good news: ", "where labels are reliable, RISKSTOP gives zero false alarms using about 15% of the budget, and its certificates always cite real attack evidence."),
    ("Memory matters for verdicts: ", "with FIFO memory, 62% of benign cases became false alarms and only 11% of attack verdicts cited real evidence; with EVICTGuard memory it was 25% and 100%."),
    ("Honest news: ", "RISKSTOP isn't yet better than the simple 'stop when evidence stalls' rule, and on OTRF/CDB it defers most cases (80–97%). The cause: our OTRF 'benign twins' probably still contain unlabelled attacker activity, so their BENIGN answers are unreliable, and CDB has only 4 benign windows."),
    ("What will improve it: ", "the LLM investigator (reads evidence semantically; needs the API key), reliable benign data from the same environment, and more test attacks."),
])
box("RISKSTOP works as designed and is safe (it defers rather than guessing), but proving it beats simple stopping rules needs the LLM step and better benign data.")
h("RISKSTOP, upgraded: real alerts and guaranteed error rates", 2)
p("We rebuilt the RISKSTOP benchmark to be realistic: every investigation starts from a real Carbon Black security alert (528 alerts: 59 real attacks, 170 false alarms raised during the attack day, 299 from normal days), on the same computers and the same sensor, with exact expert labels.")
p("We also gave RISKSTOP a statistical guarantee using a method called Learn-then-Test: its thresholds are only accepted if validation data proves, with 90% confidence, that missed attacks and false alarms stay at or below 10%.")
table([
    ["RISKSTOP (guaranteed)", "0–5%", "2–10%", "8–12%", "lowest (0.60–0.74)"],
    ["Stop when evidence stalls (BAGEN-style)", "28–32%", "3–4%", "23%", "0.80–0.86"],
    ["Stop when confident", "33–36%", "1–2%", "5%", "0.75–0.82"],
    ["Conformal deferral at the end", "9–16%", "3–5%", "97%", "1.11"],
    ["Use the whole budget", "27–35%", "6–7%", "97%", "1.21–1.36"],
], ["371 test investigations", "Missed attacks", "False alarms", "Budget used", "Expected cost"])
bullets([
    ("Headline: ", "RISKSTOP cuts missed attacks from 16–36% to 0–5% while using only about 10% of the investigation budget, and has the lowest overall cost."),
    ("The price: ", "it hands 34–48% of alerts to a human analyst when unsure. That's how the guarantee is kept."),
    ("Honest details: ", "the guarantee held fully with one memory type and was right on the boundary with the other (false alarms 10.1% vs a 10% target), because the test set includes a computer the validation set didn't. One component (the residual-risk cap) turned out unused. Calibration and the query-value rule both clearly matter."),
])
box("This is a publishable claim: on real vendor alerts, risk-controlled stopping reduces missed attacks by roughly 5× or more at about 10% of the investigation cost, with a statistical guarantee, at the price of escalating uncertain alerts.")
h("RISKSTOP with an LLM investigator (free, local Qwen2.5-7B)", 2)
p("We replaced the rule-based investigator with an LLM that reads the evidence, picks the next query and gives an attack likelihood. To keep it free and reproducible we ran an open model (Qwen2.5-7B) on the laptop. It covered all validation and test alerts under all three noise conditions (542 investigations), with a smaller budget of 12 units.")
table([
    ["RISKSTOP-LLM (guaranteed)", "16%", "1.4%", "26%", "9%", "0.68 (lowest)"],
    ["Stop when confident", "28%", "5.7%", "0%", "12%", "0.79"],
    ["Stop when evidence stalls (BAGEN-style)", "24%", "10.1%", "0%", "37%", "0.94"],
    ["Conformal deferral at the end", "15%", "6.4%", "15%", "99%", "1.10"],
    ["Use the whole budget", "23%", "10.5%", "0%", "99%", "1.23"],
    ["LLM's own verdict (no RISKSTOP)", "1%", "86%", "0%", "99%", "2.61"],
], ["371 test investigations, budget 12", "Missed attacks", "False alarms", "Escalated", "Budget used", "Expected cost"])
bullets([
    ("The LLM alone is unusable: ", "it calls almost everything an attack (86% false alarms)."),
    ("RISKSTOP makes it usable: ", "calibrating the LLM's score with Learn-then-Test cuts false alarms to 1.4% and gives the lowest cost of every policy. It is significantly cheaper than every baseline except 'stop when confident' (the difference there is not significant)."),
    ("Rule-based vs LLM: ", "at this small budget the rule-based RISKSTOP could not be certified at all, whereas the LLM version was certified on validation."),
    ("Honest limits: ", "the missed-attack guarantee did not transfer to test (16%, target 10%), because the test attacks come from different attack scenarios than validation. Decisions are made almost immediately (median: at the alert itself), so background noise did not change them. The risk models were trained on rule-based runs to save compute."),
])
box("An LLM on its own is a poor alert triager (86% false alarms); wrapped in RISKSTOP it becomes the cheapest policy with 1.4% false alarms. The missed-attack guarantee needs validation data that matches the test attacks.")

h("Second setting: validation that matches the test alerts", 2)
p("We re-split the 59 attack alerts so that validation and test contain alerts from the same attack scenarios (20 / 20 / 19). This is the condition the guarantee assumes. The earlier split, where test attacks come from unseen scenarios, is kept and reported too.")
table([
    ["RISKSTOP-LLM (guaranteed)", "0%", "0.7%", "48%", "0.56"],
    ["RISKSTOP, classifier (guaranteed)", "0%", "6.1%", "32%", "0.58"],
    ["Stop when confident", "3.5%", "7.4%", "0%", "0.36"],
    ["Use the whole budget", "7.0%", "8.1%", "0%", "0.83"],
    ["LLM's own verdict", "0%", "86%", "0%", "2.68"],
], ["353 test investigations (Qwen, budget 12)", "Missed attacks", "False alarms", "Escalated", "Expected cost"])
bullets([
    ("Guarantee holds: ", "with matching validation data, both RISKSTOP versions miss no attacks and keep false alarms under 10%."),
    ("What the LLM adds: ", "far fewer false alarms (0.7% vs 6.1%), but it escalates more alerts, so the overall cost is the same."),
    ("Honest trade-off: ", "'stop when confident' is cheaper under our cost model because it never escalates, but it has no guarantee (its missed-attack rate could be up to 12%)."),
    ("Two-setting headline: ", "same scenarios: guarantee holds. Unseen attack scenarios: false alarms stay controlled, missed attacks rise to 16%."),
])


# ------------------------------------------------------------------ 11
h("12. Likely viva questions and answers")
qa("Why didn't you use CDB as the main dataset?", "Its full data is only available on request (only a sample is public), it's built from OTRF recordings we can download ourselves, and it has no real benign data, so it can't test the BENIGN or false-alarm side. We adopted its labelling idea instead.")
qa("How do you know your labels are correct?", "Each label has a recorded reason (which rule, which attacker process). We reviewed a stratified sample, found three systematic errors, fixed them, and re-checked (30/30 core correct). Uncertain events are marked ambiguous and excluded rather than guessed. A human agreement check is the remaining step.")
qa("Why not label with an LLM like CDB?", "An LLM-based labeller would put the same kind of model we evaluate into the answer key, and results can change run to run. Our rule + process-tree method is deterministic and auditable.")
qa("How did you prevent data leakage?", "Attacks are split by ATT&CK technique family, so test techniques are unseen in training. Background is split by calendar day, after removing duplicates (ATLASv2's cumulative exports would otherwise leak the same events across splits).")
qa("Why are validation results so high but real results so low?", "Splicing Windows 10 attacks into Windows 7 background makes attack events stand out by event type, which EVICTGuard's rarity feature exploits. We measured this (83% novel event types) and harmonised it (9%), but the spliced setting stayed easy. The 16 native ATLASv2 attacks are the honest test: there the original v1 was near random, while the redesigned v2/v3 keep 0.97–0.99 of the attack evidence.")
qa("Isn't it a problem that EVICTGuard fails on real data?", "It's a finding, not a failure of the project. The evaluation pipeline is designed to expose weaknesses before deployment. It tells us the scoring needs features beyond event-type rarity.")
qa("Why Sigma rules and not your own detections?", "Sigma is a community standard with about 2,400 maintained Windows rules mapped to ATT&CK, so labels are reproducible and not tuned by us to favour our method. We pinned a specific release (r2026-04-01) for reproducibility.")
qa("Could the labelling be circular?", "Only if EVICTGuard used Sigma hits as a feature. It doesn't. If that's ever added, the rule set must be split (some rules for labels, others for features).")
qa("What is a 'core' vs 'supporting' event?", "Core: directly shows an attack action (e.g. LSASS memory dump, DCSync). Supporting: other activity of attacker processes that gives context (DLL loads, registry reads).")
qa("What does DEFER mean and how is it judged?", "DEFER means hand over to a human. It's correct for attack episodes where less than 50% of the core evidence survives. This rule was fixed before running experiments.")
qa("What exactly did you change in EVICTGuard?", "We replaced 'how rare is this event type' with seven security signals: never-seen-before programs and actions (historical prevalence), process family tree, programs running from user folders, actions on user folders vs system libraries, sensitive targets, how informative the event type is, and first-time actions with duplicates collapsed. All of them are computed without labels.")
qa("How do we know v2 isn't overfitted?", "Design used only the 10 host-1 attacks; the code was frozen (SHA-256 saved) before the 6 host-2 attacks were evaluated. v2 won on all 6 (p = 0.031). Limitation: host-2 attacks belong to the same campaigns, so a second dataset is the next step.")
qa("Why is record recall (0.51) lower than action recall (0.97)?", "Windows often logs the same action several times. ATLAS marked one particular copy; v2 keeps one copy of each action. We report both so nobody can say we picked the friendlier metric.")
qa("Did you compare against methods from your literature survey?", "Yes. We re-implemented the core ideas of NoDoze (historical anomaly + provenance propagation) and of alert prioritisation (Sigma rule hits first), plus classic rare-event anomaly and recency. On held-out real attacks, keeping 0.5% of the log, they keep 0–5% of the attack evidence; EVICTGuard keeps 97%.")
qa("Why did the baselines get almost zero? Isn't that suspicious?", "We checked. Recency keeps only recent events; Sigma rules don't fire on the attack's file activity; the anomaly methods give the same top score to thousands of new events, so the attack is lost in ties. We also found that our first tie-break (by time) unfairly pushed them to exactly 0, so we switched to random tie-breaking.")
qa("Does it work on a different environment?", "Yes. On 84 native Windows 10 OTRF attacks from a different lab, with no history at all, frozen v2 kept 58% (at 1%) and 87% (at 5%) of attack evidence, versus at most 34% for any literature baseline.")
qa("Does it work as a real streaming system?", "The online version decides event by event with fixed memory and no look-ahead: 96–97% on held-out ATLASv2, 48–80% on OTRF. It's slightly below batch on the small OTRF episodes.")
qa("Did you test on data labelled by someone else?", "Yes: the CDB public campaign, with CDB's own labels. We found that 70% of its core labels are an Azure cloud agent (very likely false alarms), and on CDB EVICTGuard is only comparable to a simple rare-event baseline. We report that openly as a limitation.")
qa("How reliable are your labels?", "ATLASv2's labels come from the dataset's experts and are the most reliable. For OTRF we built our own; when compared with CDB's independent labeller on the same events, agreement was only slight (kappa 0.08–0.19), which shows how uncertain automatic labels are. A human check is prepared.")
qa("What is RISKSTOP's main result?", "On 371 test investigations that start from real Carbon Black alerts, RISKSTOP misses 0–5% of attacks versus 16–36% for every baseline, uses about 10% of the investigation budget, and has the lowest expected cost. Its thresholds are certified by Learn-then-Test so error rates stay at or below 10% with 90% confidence; the trade-off is that it escalates 34–48% of alerts to a human.")
qa("Does the guarantee always hold?", "It held fully with FIFO memory. With EVICTGuard memory the false-alarm rate was 10.1% against a 10% target (inside the statistical margin), because the test set includes a host the validation set didn't. Distribution-free guarantees assume validation and test look alike; we state that limitation.")
qa("How big is the data and can it run on a laptop?", "About 1.5M OTRF events and about 460k ATLASv2 benign events plus 16 attack scenarios. Disk use is under 1 GB, peak RAM about 3.6 GB, and ATLASv2 is streamed so its 160 GB is never stored.")

# ------------------------------------------------------------------ 12
h("13. Glossary")
table([
    ["SOC", "Security Operations Centre: team that monitors and investigates alerts"],
    ["Telemetry / log event", "One recorded action on a computer (process started, file written, login)"],
    ["Sysmon", "Microsoft tool that logs detailed process, network, and registry activity"],
    ["ATT&CK", "MITRE's catalogue of attacker techniques (e.g. T1003 = credential dumping)"],
    ["Sigma rule", "A shareable detection rule describing suspicious log patterns"],
    ["ProcessGuid", "Unique ID of a running program; lets us build the parent → child tree"],
    ["Episode", "One practice investigation: a set of events with a known correct verdict"],
    ["Splicing", "Inserting attack events into a slice of normal activity"],
    ["OOD (out-of-distribution)", "Test data unlike the training data: here, real ATLASv2 attacks"],
    ["Recall", "Share of the important items that were kept"],
    ["FIFO", "First-in-first-out: keep only the newest events"],
    ["Leakage", "Test information sneaking into training, which makes results look better than they are"],
    ["REAPr", "Published, standardised ground-truth labels for ATLASv2 attack processes"],
], ["Term", "Meaning"])

# ------------------------------------------------------------------ 13
h("14. How to run everything")
p("From the project folder (~/EVICTGuard_extract/EVICTGuard):")
bullets([
    "./run_pipeline.sh atlasv2 runs the whole pipeline, skipping steps already done.",
    "python -m pytest -q runs all 31 tests.",
    "python -m src.run_benchmark --split ood runs the realistic benchmark.",
    "Details: docs/DATASET.md.",
])

OUT.parent.mkdir(parents=True, exist_ok=True)
doc.save(OUT)
print(f"saved {OUT} (OOD results {'included' if ood_ok else 'pending'})")
