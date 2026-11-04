# Slide 11 (replacement): Methodology To Be Used : Datasets

## Plain text (for PowerPoint / Google Slides)

**Methodology To Be Used : Datasets**

- **OTRF Security-Datasets (Rodriguez, 2020) [11]: attack pool.** 110 recorded Windows attack
  scenarios (Sysmon, Security, PowerShell logs; about 1.5M events) mapped to MITRE ATT&CK.
  Event-level labels are constructed with Sigma rules plus process-ancestry tracing, giving
  *core / supporting / ambiguous / background* evidence tiers.
- **ATLASv2 (Riddle et al., 2023): benign background and out-of-distribution test.** Four
  days of real, human-generated benign Windows activity, plus 10 attacks with REAPr
  process-level ground truth.
- **Episode construction and noise injection.** Attacks are spliced into benign windows to
  form labelled ATTACK / BENIGN investigation episodes, split train/val/test by ATT&CK
  technique (no leakage). Telemetry flooding, duplicated events, benign-looking floods,
  adversarial mimic floods and missing evidence are injected with labels preserved.
- *Cyber Defense Benchmark (Chona et al., 2026) [7]: its Sigma-based labelling approach is
  adapted. The full benchmark is only available on request.*

## Optional extra slide: Ground-Truth Labelling

- **Root causes:** attacker processes named in OTRF's adversary console logs, plus high-severity
  Sigma hits on process creation
- **Causal expansion:** process-tree tracing (ProcessGuid → ParentProcessGuid), adapted from REAPr
- **Tiers:** *core* = Sigma hit inside the attack tree, or matching the documented ATT&CK technique;
  *supporting* = other activity of attacker processes; *ambiguous* = excluded from scoring
- **Validation:** stratified manual review of sampled labels; agreement is reported
- **Gold RISKSTOP verdicts:** BENIGN episode → BENIGN; ATTACK with ≥ 50% of core evidence left → ATTACK; otherwise → DEFER

## Beamer (LaTeX) frames

```latex
\begin{frame}{Methodology To Be Used : Datasets}
\begin{itemize}
  \item \textbf{OTRF Security-Datasets -- Rodriguez, 2020 [11]} \\
        Attack pool: 110 recorded Windows attack scenarios (Sysmon, Security, PowerShell; $\sim$1.5M events)
        mapped to ATT\&CK; event-level labels constructed via Sigma rules + process-ancestry tracing.
  \item \textbf{ATLASv2 -- Riddle et al., 2023} \\
        Real human-generated benign background (4 days) and an out-of-distribution attack test set
        with REAPr process-level ground truth.
  \item \textbf{Episodes \& Noise Injection} \\
        Attacks spliced into benign windows $\rightarrow$ labelled ATTACK/BENIGN episodes, split by ATT\&CK technique;
        flooding, duplicates, benign-looking and adversarial mimic floods, and missing evidence injected with labels preserved.
\end{itemize}
\vspace{0.3em}
{\small\textit{Cyber Defense Benchmark (Chona et al., 2026) [7]: Sigma-based labelling approach adapted; full benchmark available only on request.}}
\end{frame}

\begin{frame}{Methodology To Be Used : Ground-Truth Labelling}
\begin{itemize}
  \item \textbf{Root causes:} attacker processes from OTRF adversary console logs + high-severity Sigma hits
  \item \textbf{Causal expansion:} process-tree tracing (ProcessGuid $\rightarrow$ ParentProcessGuid), adapted from REAPr
  \item \textbf{Evidence tiers:} core / supporting / ambiguous (excluded) / background
  \item \textbf{Validation:} stratified manual review of sampled labels
  \item \textbf{Gold RISKSTOP verdicts:} BENIGN $\rightarrow$ BENIGN; ATTACK with $\geq$50\% core evidence $\rightarrow$ ATTACK; else DEFER
\end{itemize}
\end{frame}
```

Add to the references:
`[12] A. Riddle, K. Westfall, and A. Bates. "ATLASv2: ATLAS Attack Engagements, Version 2," arXiv:2401.01341, 2023.`
