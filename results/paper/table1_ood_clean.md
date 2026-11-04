| subset           |   capacity | method                     |   episodes | core action recall [95% CI]   |   core record recall | core AP   | kept / input   |
|:-----------------|-----------:|:---------------------------|-----------:|:------------------------------|---------------------:|:----------|:---------------|
| development (h1) |        256 | EVICTGuard v2 (ours)       |         10 | 0.550 [0.415, 0.678]          |                0.199 | 0.139     | 0.11%          |
| development (h1) |        256 | NoDoze-style triage        |         10 | 0.000 [0.000, 0.000]          |                0     | 0.002     | 0.11%          |
| development (h1) |        256 | Sigma alert prioritisation |         10 | 0.009 [0.003, 0.015]          |                0.003 | 0.005     | 0.11%          |
| development (h1) |        256 | Rare-action anomaly        |         10 | 0.007 [0.004, 0.010]          |                0.003 | 0.002     | 0.11%          |
| development (h1) |        256 | Recency + dedup            |         10 | 0.001 [0.000, 0.003]          |                0     | 0.001     | 0.11%          |
| development (h1) |        256 | Random                     |         10 | 0.002 [0.001, 0.005]          |                0.001 | n/a       | 0.11%          |
| development (h1) |        256 | FIFO                       |         10 | 0.001 [0.000, 0.002]          |                0     | n/a       | 0.11%          |
| development (h1) |       1024 | EVICTGuard v2 (ours)       |         10 | 0.821 [0.762, 0.872]          |                0.272 | 0.139     | 0.44%          |
| development (h1) |       1024 | NoDoze-style triage        |         10 | 0.001 [0.000, 0.003]          |                0     | 0.002     | 0.44%          |
| development (h1) |       1024 | Sigma alert prioritisation |         10 | 0.010 [0.004, 0.016]          |                0.003 | 0.005     | 0.44%          |
| development (h1) |       1024 | Rare-action anomaly        |         10 | 0.028 [0.015, 0.042]          |                0.01  | 0.002     | 0.44%          |
| development (h1) |       1024 | Recency + dedup            |         10 | 0.001 [0.000, 0.003]          |                0     | 0.001     | 0.44%          |
| development (h1) |       1024 | EVICTGuard v1              |         10 | 0.030 [0.016, 0.043]          |                0.011 | 0.001     | 0.44%          |
| development (h1) |       1024 | Random                     |         10 | 0.022 [0.017, 0.026]          |                0.005 | n/a       | 0.44%          |
| development (h1) |       1024 | FIFO                       |         10 | 0.001 [0.000, 0.003]          |                0     | n/a       | 0.44%          |
| development (h1) |       4096 | EVICTGuard v2 (ours)       |         10 | 0.869 [0.814, 0.917]          |                0.286 | 0.139     | 1.74%          |
| development (h1) |       4096 | NoDoze-style triage        |         10 | 0.017 [0.007, 0.030]          |                0.003 | 0.002     | 1.74%          |
| development (h1) |       4096 | Sigma alert prioritisation |         10 | 0.010 [0.004, 0.016]          |                0.003 | 0.005     | 1.74%          |
| development (h1) |       4096 | Rare-action anomaly        |         10 | 0.115 [0.073, 0.155]          |                0.042 | 0.002     | 1.74%          |
| development (h1) |       4096 | Recency + dedup            |         10 | 0.050 [0.020, 0.086]          |                0.006 | 0.001     | 1.74%          |
| development (h1) |       4096 | EVICTGuard v1              |         10 | 0.066 [0.050, 0.083]          |                0.027 | 0.001     | 1.74%          |
| development (h1) |       4096 | Random                     |         10 | 0.055 [0.048, 0.062]          |                0.017 | n/a       | 1.74%          |
| development (h1) |       4096 | FIFO                       |         10 | 0.001 [0.000, 0.003]          |                0     | n/a       | 1.74%          |
| held-out (h2)    |        256 | EVICTGuard v2 (ours)       |          6 | 0.790 [0.594, 0.893]          |                0.448 | 0.377     | 0.13%          |
| held-out (h2)    |        256 | NoDoze-style triage        |          6 | 0.004 [0.000, 0.008]          |                0.002 | 0.002     | 0.13%          |
| held-out (h2)    |        256 | Sigma alert prioritisation |          6 | 0.000 [0.000, 0.000]          |                0     | 0.001     | 0.13%          |
| held-out (h2)    |        256 | Rare-action anomaly        |          6 | 0.014 [0.004, 0.023]          |                0.008 | 0.002     | 0.13%          |
| held-out (h2)    |        256 | Recency + dedup            |          6 | 0.000 [0.000, 0.000]          |                0     | 0.001     | 0.13%          |
| held-out (h2)    |        256 | Random                     |          6 | 0.004 [0.000, 0.008]          |                0.001 | n/a       | 0.13%          |
| held-out (h2)    |        256 | FIFO                       |          6 | 0.000 [0.000, 0.000]          |                0     | n/a       | 0.13%          |
| held-out (h2)    |       1024 | EVICTGuard v2 (ours)       |          6 | 0.973 [0.960, 0.982]          |                0.507 | 0.377     | 0.51%          |
| held-out (h2)    |       1024 | NoDoze-style triage        |          6 | 0.006 [0.002, 0.010]          |                0.003 | 0.002     | 0.51%          |
| held-out (h2)    |       1024 | Sigma alert prioritisation |          6 | 0.000 [0.000, 0.000]          |                0     | 0.001     | 0.51%          |
| held-out (h2)    |       1024 | Rare-action anomaly        |          6 | 0.048 [0.025, 0.073]          |                0.028 | 0.002     | 0.51%          |
| held-out (h2)    |       1024 | Recency + dedup            |          6 | 0.000 [0.000, 0.000]          |                0     | 0.001     | 0.51%          |
| held-out (h2)    |       1024 | EVICTGuard v1              |          6 | 0.000 [0.000, 0.000]          |                0     | 0.001     | 0.51%          |
| held-out (h2)    |       1024 | Random                     |          6 | 0.015 [0.006, 0.025]          |                0.007 | n/a       | 0.51%          |
| held-out (h2)    |       1024 | FIFO                       |          6 | 0.000 [0.000, 0.000]          |                0     | n/a       | 0.51%          |
| held-out (h2)    |       4096 | EVICTGuard v2 (ours)       |          6 | 0.985 [0.972, 0.994]          |                0.51  | 0.377     | 2.03%          |
| held-out (h2)    |       4096 | NoDoze-style triage        |          6 | 0.021 [0.015, 0.027]          |                0.012 | 0.002     | 2.03%          |
| held-out (h2)    |       4096 | Sigma alert prioritisation |          6 | 0.000 [0.000, 0.000]          |                0     | 0.001     | 2.03%          |
| held-out (h2)    |       4096 | Rare-action anomaly        |          6 | 0.167 [0.101, 0.222]          |                0.097 | 0.002     | 2.03%          |
| held-out (h2)    |       4096 | Recency + dedup            |          6 | 0.004 [0.000, 0.011]          |                0     | 0.001     | 2.03%          |
| held-out (h2)    |       4096 | EVICTGuard v1              |          6 | 0.023 [0.023, 0.023]          |                0.013 | 0.001     | 2.03%          |
| held-out (h2)    |       4096 | Random                     |          6 | 0.031 [0.021, 0.043]          |                0.018 | n/a       | 2.03%          |
| held-out (h2)    |       4096 | FIFO                       |          6 | 0.000 [0.000, 0.000]          |                0     | n/a       | 2.03%          |