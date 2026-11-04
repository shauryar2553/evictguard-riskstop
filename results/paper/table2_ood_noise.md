| subset           | noise              | method                     | core action recall [95% CI]   |   injected-noise share of context |
|:-----------------|:-------------------|:---------------------------|:------------------------------|----------------------------------:|
| development (h1) | none               | EVICTGuard v2 (ours)       | 0.821 [0.762, 0.872]          |                             0     |
| development (h1) | none               | NoDoze-style triage        | 0.001 [0.000, 0.003]          |                             0     |
| development (h1) | none               | Sigma alert prioritisation | 0.010 [0.004, 0.016]          |                             0     |
| development (h1) | none               | Rare-action anomaly        | 0.028 [0.015, 0.042]          |                             0     |
| development (h1) | none               | Recency + dedup            | 0.001 [0.000, 0.003]          |                             0     |
| development (h1) | none               | EVICTGuard v1              | 0.030 [0.016, 0.043]          |                             0     |
| development (h1) | none               | Random                     | 0.022 [0.017, 0.026]          |                             0     |
| development (h1) | none               | FIFO                       | 0.001 [0.000, 0.003]          |                             0     |
| development (h1) | duplicate-flooding | EVICTGuard v2 (ours)       | 0.811 [0.754, 0.860]          |                             0     |
| development (h1) | duplicate-flooding | Random                     | 0.020 [0.011, 0.029]          |                             0.302 |
| development (h1) | duplicate-flooding | FIFO                       | 0.001 [0.000, 0.003]          |                             0.345 |
| development (h1) | background-flood   | EVICTGuard v2 (ours)       | 0.823 [0.764, 0.874]          |                             0.021 |
| development (h1) | background-flood   | NoDoze-style triage        | 0.003 [0.000, 0.008]          |                             0     |
| development (h1) | background-flood   | Sigma alert prioritisation | 0.010 [0.004, 0.016]          |                             0.424 |
| development (h1) | background-flood   | Rare-action anomaly        | 0.042 [0.023, 0.062]          |                             0     |
| development (h1) | background-flood   | Recency + dedup            | 0.005 [0.000, 0.011]          |                             0.541 |
| development (h1) | background-flood   | Random                     | 0.013 [0.007, 0.019]          |                             0.302 |
| development (h1) | background-flood   | FIFO                       | 0.002 [0.000, 0.005]          |                             0.425 |
| development (h1) | mimic-flood        | EVICTGuard v2 (ours)       | 0.820 [0.760, 0.872]          |                             0.013 |
| development (h1) | mimic-flood        | Random                     | 0.009 [0.004, 0.015]          |                             0.158 |
| development (h1) | mimic-flood        | FIFO                       | 0.001 [0.000, 0.003]          |                             0.211 |
| held-out (h2)    | none               | EVICTGuard v2 (ours)       | 0.973 [0.960, 0.982]          |                             0     |
| held-out (h2)    | none               | NoDoze-style triage        | 0.006 [0.002, 0.010]          |                             0     |
| held-out (h2)    | none               | Sigma alert prioritisation | 0.000 [0.000, 0.000]          |                             0     |
| held-out (h2)    | none               | Rare-action anomaly        | 0.048 [0.025, 0.073]          |                             0     |
| held-out (h2)    | none               | Recency + dedup            | 0.000 [0.000, 0.000]          |                             0     |
| held-out (h2)    | none               | EVICTGuard v1              | 0.000 [0.000, 0.000]          |                             0     |
| held-out (h2)    | none               | Random                     | 0.015 [0.006, 0.025]          |                             0     |
| held-out (h2)    | none               | FIFO                       | 0.000 [0.000, 0.000]          |                             0     |
| held-out (h2)    | duplicate-flooding | EVICTGuard v2 (ours)       | 0.973 [0.960, 0.982]          |                             0     |
| held-out (h2)    | duplicate-flooding | Random                     | 0.008 [0.004, 0.012]          |                             0.303 |
| held-out (h2)    | duplicate-flooding | FIFO                       | 0.000 [0.000, 0.000]          |                             0.339 |
| held-out (h2)    | background-flood   | EVICTGuard v2 (ours)       | 0.973 [0.960, 0.982]          |                             0.025 |
| held-out (h2)    | background-flood   | NoDoze-style triage        | 0.008 [0.002, 0.015]          |                             0     |
| held-out (h2)    | background-flood   | Sigma alert prioritisation | 0.000 [0.000, 0.000]          |                             0.636 |
| held-out (h2)    | background-flood   | Rare-action anomaly        | 0.062 [0.035, 0.080]          |                             0     |
| held-out (h2)    | background-flood   | Recency + dedup            | 0.000 [0.000, 0.000]          |                             0.503 |
| held-out (h2)    | background-flood   | Random                     | 0.008 [0.004, 0.012]          |                             0.303 |
| held-out (h2)    | background-flood   | FIFO                       | 0.000 [0.000, 0.000]          |                             0.636 |
| held-out (h2)    | mimic-flood        | EVICTGuard v2 (ours)       | 0.973 [0.960, 0.982]          |                             0.022 |
| held-out (h2)    | mimic-flood        | Random                     | 0.010 [0.004, 0.016]          |                             0.16  |
| held-out (h2)    | mimic-flood        | FIFO                       | 0.000 [0.000, 0.000]          |                             0.327 |