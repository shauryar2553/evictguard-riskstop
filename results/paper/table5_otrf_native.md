Native OTRF episodes (real attack + real lab background, Windows 10), cold start (no history). Frozen EVICTGuard v2 never saw this dataset.

| split            |   capacity (fraction) | noise              | method               |   episodes | core action recall [95% CI]   |
|:-----------------|----------------------:|:-------------------|:---------------------|-----------:|:------------------------------|
| otrf_native_test |                  0.01 | background-flood   | EVICTGuard v2 (ours) |         17 | 0.608 [0.402, 0.814]          |
| otrf_native_test |                  0.01 | background-flood   | NoDoze-style triage  |         17 | 0.083 [0.015, 0.167]          |
| otrf_native_test |                  0.01 | background-flood   | Rare-action anomaly  |         17 | 0.049 [0.000, 0.118]          |
| otrf_native_test |                  0.01 | background-flood   | Recency + dedup      |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | background-flood   | EVICTGuard v1        |         17 | 0.294 [0.147, 0.466]          |
| otrf_native_test |                  0.01 | background-flood   | Random               |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | background-flood   | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | duplicate-flooding | EVICTGuard v2 (ours) |         17 | 0.520 [0.314, 0.725]          |
| otrf_native_test |                  0.01 | duplicate-flooding | NoDoze-style triage  |         17 | 0.078 [0.015, 0.157]          |
| otrf_native_test |                  0.01 | duplicate-flooding | Rare-action anomaly  |         17 | 0.064 [0.000, 0.137]          |
| otrf_native_test |                  0.01 | duplicate-flooding | Recency + dedup      |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | duplicate-flooding | EVICTGuard v1        |         17 | 0.294 [0.147, 0.466]          |
| otrf_native_test |                  0.01 | duplicate-flooding | Random               |         17 | 0.088 [0.000, 0.235]          |
| otrf_native_test |                  0.01 | duplicate-flooding | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | mimic-flood        | EVICTGuard v2 (ours) |         17 | 0.593 [0.382, 0.804]          |
| otrf_native_test |                  0.01 | mimic-flood        | NoDoze-style triage  |         17 | 0.078 [0.000, 0.167]          |
| otrf_native_test |                  0.01 | mimic-flood        | Rare-action anomaly  |         17 | 0.034 [0.000, 0.083]          |
| otrf_native_test |                  0.01 | mimic-flood        | Recency + dedup      |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | mimic-flood        | EVICTGuard v1        |         17 | 0.250 [0.098, 0.422]          |
| otrf_native_test |                  0.01 | mimic-flood        | Random               |         17 | 0.015 [0.000, 0.044]          |
| otrf_native_test |                  0.01 | mimic-flood        | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | none               | EVICTGuard v2 (ours) |         17 | 0.578 [0.368, 0.794]          |
| otrf_native_test |                  0.01 | none               | NoDoze-style triage  |         17 | 0.044 [0.000, 0.118]          |
| otrf_native_test |                  0.01 | none               | Rare-action anomaly  |         17 | 0.074 [0.000, 0.206]          |
| otrf_native_test |                  0.01 | none               | Recency + dedup      |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.01 | none               | EVICTGuard v1        |         17 | 0.191 [0.064, 0.338]          |
| otrf_native_test |                  0.01 | none               | Random               |         17 | 0.020 [0.000, 0.059]          |
| otrf_native_test |                  0.01 | none               | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.05 | background-flood   | EVICTGuard v2 (ours) |         17 | 0.926 [0.828, 1.000]          |
| otrf_native_test |                  0.05 | background-flood   | NoDoze-style triage  |         17 | 0.382 [0.211, 0.583]          |
| otrf_native_test |                  0.05 | background-flood   | Rare-action anomaly  |         17 | 0.637 [0.426, 0.838]          |
| otrf_native_test |                  0.05 | background-flood   | Recency + dedup      |         17 | 0.020 [0.000, 0.059]          |
| otrf_native_test |                  0.05 | background-flood   | EVICTGuard v1        |         17 | 0.686 [0.475, 0.873]          |
| otrf_native_test |                  0.05 | background-flood   | Random               |         17 | 0.015 [0.000, 0.044]          |
| otrf_native_test |                  0.05 | background-flood   | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.05 | duplicate-flooding | EVICTGuard v2 (ours) |         17 | 0.907 [0.789, 1.000]          |
| otrf_native_test |                  0.05 | duplicate-flooding | NoDoze-style triage  |         17 | 0.353 [0.176, 0.554]          |
| otrf_native_test |                  0.05 | duplicate-flooding | Rare-action anomaly  |         17 | 0.461 [0.255, 0.672]          |
| otrf_native_test |                  0.05 | duplicate-flooding | Recency + dedup      |         17 | 0.113 [0.000, 0.255]          |
| otrf_native_test |                  0.05 | duplicate-flooding | EVICTGuard v1        |         17 | 0.686 [0.475, 0.873]          |
| otrf_native_test |                  0.05 | duplicate-flooding | Random               |         17 | 0.015 [0.000, 0.044]          |
| otrf_native_test |                  0.05 | duplicate-flooding | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.05 | mimic-flood        | EVICTGuard v2 (ours) |         17 | 0.892 [0.784, 0.985]          |
| otrf_native_test |                  0.05 | mimic-flood        | NoDoze-style triage  |         17 | 0.275 [0.098, 0.471]          |
| otrf_native_test |                  0.05 | mimic-flood        | Rare-action anomaly  |         17 | 0.377 [0.186, 0.569]          |
| otrf_native_test |                  0.05 | mimic-flood        | Recency + dedup      |         17 | 0.078 [0.000, 0.216]          |
| otrf_native_test |                  0.05 | mimic-flood        | EVICTGuard v1        |         17 | 0.623 [0.412, 0.814]          |
| otrf_native_test |                  0.05 | mimic-flood        | Random               |         17 | 0.039 [0.000, 0.098]          |
| otrf_native_test |                  0.05 | mimic-flood        | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_test |                  0.05 | none               | EVICTGuard v2 (ours) |         17 | 0.873 [0.730, 0.985]          |
| otrf_native_test |                  0.05 | none               | NoDoze-style triage  |         17 | 0.279 [0.113, 0.471]          |
| otrf_native_test |                  0.05 | none               | Rare-action anomaly  |         17 | 0.338 [0.132, 0.544]          |
| otrf_native_test |                  0.05 | none               | Recency + dedup      |         17 | 0.078 [0.000, 0.216]          |
| otrf_native_test |                  0.05 | none               | EVICTGuard v1        |         17 | 0.667 [0.466, 0.848]          |
| otrf_native_test |                  0.05 | none               | Random               |         17 | 0.020 [0.000, 0.059]          |
| otrf_native_test |                  0.05 | none               | FIFO                 |         17 | 0.000 [0.000, 0.000]          |
| otrf_native_val  |                  0.01 | background-flood   | EVICTGuard v2 (ours) |         17 | 0.611 [0.419, 0.784]          |
| otrf_native_val  |                  0.01 | background-flood   | Recency + dedup      |         17 | 0.053 [0.000, 0.128]          |
| otrf_native_val  |                  0.01 | background-flood   | EVICTGuard v1        |         17 | 0.194 [0.062, 0.348]          |
| otrf_native_val  |                  0.01 | background-flood   | Random               |         17 | 0.132 [0.008, 0.302]          |
| otrf_native_val  |                  0.01 | background-flood   | FIFO                 |         17 | 0.025 [0.000, 0.071]          |
| otrf_native_val  |                  0.01 | duplicate-flooding | EVICTGuard v2 (ours) |         17 | 0.635 [0.435, 0.806]          |
| otrf_native_val  |                  0.01 | duplicate-flooding | Recency + dedup      |         17 | 0.384 [0.187, 0.588]          |
| otrf_native_val  |                  0.01 | duplicate-flooding | EVICTGuard v1        |         17 | 0.195 [0.063, 0.350]          |
| otrf_native_val  |                  0.01 | duplicate-flooding | Random               |         17 | 0.136 [0.012, 0.307]          |
| otrf_native_val  |                  0.01 | duplicate-flooding | FIFO                 |         17 | 0.041 [0.000, 0.100]          |
| otrf_native_val  |                  0.01 | mimic-flood        | EVICTGuard v2 (ours) |         17 | 0.404 [0.240, 0.573]          |
| otrf_native_val  |                  0.01 | mimic-flood        | Recency + dedup      |         17 | 0.168 [0.031, 0.336]          |
| otrf_native_val  |                  0.01 | mimic-flood        | EVICTGuard v1        |         17 | 0.194 [0.062, 0.348]          |
| otrf_native_val  |                  0.01 | mimic-flood        | Random               |         17 | 0.045 [0.002, 0.094]          |
| otrf_native_val  |                  0.01 | mimic-flood        | FIFO                 |         17 | 0.025 [0.000, 0.071]          |
| otrf_native_val  |                  0.01 | none               | EVICTGuard v2 (ours) |         17 | 0.303 [0.151, 0.468]          |
| otrf_native_val  |                  0.01 | none               | Recency + dedup      |         17 | 0.079 [0.005, 0.171]          |
| otrf_native_val  |                  0.01 | none               | EVICTGuard v1        |         17 | 0.188 [0.054, 0.343]          |
| otrf_native_val  |                  0.01 | none               | Random               |         17 | 0.099 [0.005, 0.240]          |
| otrf_native_val  |                  0.01 | none               | FIFO                 |         17 | 0.041 [0.000, 0.100]          |
| otrf_native_val  |                  0.05 | background-flood   | EVICTGuard v2 (ours) |         17 | 0.935 [0.845, 1.000]          |
| otrf_native_val  |                  0.05 | background-flood   | Recency + dedup      |         17 | 0.480 [0.245, 0.698]          |
| otrf_native_val  |                  0.05 | background-flood   | EVICTGuard v1        |         17 | 0.359 [0.193, 0.531]          |
| otrf_native_val  |                  0.05 | background-flood   | Random               |         17 | 0.107 [0.040, 0.186]          |
| otrf_native_val  |                  0.05 | background-flood   | FIFO                 |         17 | 0.070 [0.005, 0.151]          |
| otrf_native_val  |                  0.05 | duplicate-flooding | EVICTGuard v2 (ours) |         17 | 0.932 [0.839, 1.000]          |
| otrf_native_val  |                  0.05 | duplicate-flooding | Recency + dedup      |         17 | 0.690 [0.489, 0.862]          |
| otrf_native_val  |                  0.05 | duplicate-flooding | EVICTGuard v1        |         17 | 0.394 [0.214, 0.575]          |
| otrf_native_val  |                  0.05 | duplicate-flooding | Random               |         17 | 0.113 [0.044, 0.194]          |
| otrf_native_val  |                  0.05 | duplicate-flooding | FIFO                 |         17 | 0.050 [0.000, 0.126]          |
| otrf_native_val  |                  0.05 | mimic-flood        | EVICTGuard v2 (ours) |         17 | 0.924 [0.828, 1.000]          |
| otrf_native_val  |                  0.05 | mimic-flood        | Recency + dedup      |         17 | 0.485 [0.268, 0.706]          |
| otrf_native_val  |                  0.05 | mimic-flood        | EVICTGuard v1        |         17 | 0.330 [0.178, 0.492]          |
| otrf_native_val  |                  0.05 | mimic-flood        | Random               |         17 | 0.133 [0.029, 0.269]          |
| otrf_native_val  |                  0.05 | mimic-flood        | FIFO                 |         17 | 0.045 [0.000, 0.112]          |
| otrf_native_val  |                  0.05 | none               | EVICTGuard v2 (ours) |         17 | 0.889 [0.772, 0.977]          |
| otrf_native_val  |                  0.05 | none               | Recency + dedup      |         17 | 0.481 [0.267, 0.699]          |
| otrf_native_val  |                  0.05 | none               | EVICTGuard v1        |         17 | 0.330 [0.178, 0.492]          |
| otrf_native_val  |                  0.05 | none               | Random               |         17 | 0.125 [0.024, 0.264]          |
| otrf_native_val  |                  0.05 | none               | FIFO                 |         17 | 0.050 [0.000, 0.126]          |