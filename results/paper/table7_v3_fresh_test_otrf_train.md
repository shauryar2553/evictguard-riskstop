EVICTGuard v3 (frozen, results/evictguard_v3.json) on its fresh test: OTRF native train split, cold start.

|   capacity (fraction) | noise            | method               |   episodes | core action recall [95% CI]   |
|----------------------:|:-----------------|:---------------------|-----------:|:------------------------------|
|                  0.01 | background-flood | EVICTGuard v2 (ours) |         50 | 0.550 [0.440, 0.660]          |
|                  0.01 | background-flood | EVICTGuard v3        |         50 | 0.550 [0.442, 0.659]          |
|                  0.01 | background-flood | NoDoze-style triage  |         50 | 0.142 [0.064, 0.230]          |
|                  0.01 | background-flood | Rare-action anomaly  |         50 | 0.205 [0.119, 0.301]          |
|                  0.01 | background-flood | Recency + dedup      |         50 | 0.033 [0.000, 0.083]          |
|                  0.01 | background-flood | EVICTGuard v1        |         50 | 0.272 [0.180, 0.374]          |
|                  0.01 | background-flood | Random               |         50 | 0.024 [0.000, 0.060]          |
|                  0.01 | background-flood | FIFO                 |         50 | 0.015 [0.000, 0.037]          |
|                  0.01 | none             | EVICTGuard v2 (ours) |         50 | 0.436 [0.322, 0.557]          |
|                  0.01 | none             | EVICTGuard v3        |         50 | 0.396 [0.289, 0.511]          |
|                  0.01 | none             | NoDoze-style triage  |         50 | 0.105 [0.038, 0.184]          |
|                  0.01 | none             | Rare-action anomaly  |         50 | 0.125 [0.059, 0.199]          |
|                  0.01 | none             | Recency + dedup      |         50 | 0.041 [0.003, 0.094]          |
|                  0.01 | none             | EVICTGuard v1        |         50 | 0.171 [0.099, 0.248]          |
|                  0.01 | none             | Random               |         50 | 0.025 [0.003, 0.053]          |
|                  0.01 | none             | FIFO                 |         50 | 0.015 [0.000, 0.037]          |
|                  0.05 | background-flood | EVICTGuard v2 (ours) |         50 | 0.832 [0.738, 0.914]          |
|                  0.05 | background-flood | EVICTGuard v3        |         50 | 0.836 [0.747, 0.918]          |
|                  0.05 | background-flood | NoDoze-style triage  |         50 | 0.412 [0.297, 0.527]          |
|                  0.05 | background-flood | Rare-action anomaly  |         50 | 0.539 [0.421, 0.654]          |
|                  0.05 | background-flood | Recency + dedup      |         50 | 0.213 [0.111, 0.321]          |
|                  0.05 | background-flood | EVICTGuard v1        |         50 | 0.615 [0.502, 0.717]          |
|                  0.05 | background-flood | Random               |         50 | 0.067 [0.029, 0.118]          |
|                  0.05 | background-flood | FIFO                 |         50 | 0.035 [0.000, 0.088]          |
|                  0.05 | none             | EVICTGuard v2 (ours) |         50 | 0.745 [0.638, 0.844]          |
|                  0.05 | none             | EVICTGuard v3        |         50 | 0.766 [0.662, 0.865]          |
|                  0.05 | none             | NoDoze-style triage  |         50 | 0.311 [0.205, 0.424]          |
|                  0.05 | none             | Rare-action anomaly  |         50 | 0.389 [0.275, 0.505]          |
|                  0.05 | none             | Recency + dedup      |         50 | 0.165 [0.075, 0.265]          |
|                  0.05 | none             | EVICTGuard v1        |         50 | 0.506 [0.394, 0.619]          |
|                  0.05 | none             | Random               |         50 | 0.100 [0.043, 0.167]          |
|                  0.05 | none             | FIFO                 |         50 | 0.015 [0.000, 0.037]          |