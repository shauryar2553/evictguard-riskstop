RISKSTOP vs stopping baselines on TEST investigations (no LLM; heuristic investigator), by memory and domain

| memory     | policy                        | domain   |   n |   accuracy |   missed_attack_rate |   false_alarm_rate |   defer_rate |   correct_defer_rate |   budget_used |   grounded_attack_rate |
|:-----------|:------------------------------|:---------|----:|-----------:|---------------------:|-------------------:|-------------:|---------------------:|--------------:|-----------------------:|
| evictguard | BAGEN-style (gain stall)      | ALL      | 169 |      0.538 |                0.187 |              0.565 |        0     |                0     |         0.182 |                  0.51  |
| evictguard | Confidence stop               | ALL      | 169 |      0.55  |                0.146 |              0.609 |        0     |                0     |         0.723 |                  0.543 |
| evictguard | Conformal deferral (end only) | ALL      | 169 |      0.32  |                0.057 |              0     |        0.775 |                0.784 |         0.98  |                  1     |
| evictguard | Fixed budget                  | ALL      | 169 |      0.544 |                0.138 |              0.63  |        0     |                0     |         0.98  |                  0.547 |
| evictguard | RISKSTOP                      | ALL      | 169 |      0.32  |                0.13  |              0.043 |        0.692 |                0.676 |         0.183 |                  0.85  |
| fifo       | BAGEN-style (gain stall)      | ALL      | 169 |      0.497 |                0.22  |              0.63  |        0     |                0     |         0.177 |                  0.5   |
| fifo       | Confidence stop               | ALL      | 169 |      0.556 |                0.195 |              0.5   |        0     |                0     |         0.797 |                  0.374 |
| fifo       | Conformal deferral (end only) | ALL      | 169 |      0.29  |                0.041 |              0     |        0.87  |                0.919 |         0.978 |                  0.231 |
| fifo       | Fixed budget                  | ALL      | 169 |      0.533 |                0.195 |              0.587 |        0     |                0     |         0.978 |                  0.222 |
| fifo       | RISKSTOP                      | ALL      | 169 |      0.337 |                0.049 |              0.043 |        0.763 |                0.811 |         0.212 |                  0.857 |
| evictguard | BAGEN-style (gain stall)      | atlas    |  26 |      0.769 |                0     |              0     |        0     |                0     |         0.223 |                  1     |
| evictguard | Confidence stop               | atlas    |  26 |      0.692 |                0.056 |              0.25  |        0     |                0     |         0.094 |                  1     |
| evictguard | Conformal deferral (end only) | atlas    |  26 |      0.692 |                0     |              0     |        0.077 |                0     |         0.99  |                  1     |
| evictguard | Fixed budget                  | atlas    |  26 |      0.692 |                0     |              0.25  |        0     |                0     |         0.99  |                  1     |
| evictguard | RISKSTOP                      | atlas    |  26 |      0.731 |                0.056 |              0     |        0.038 |                0     |         0.15  |                  1     |
| fifo       | BAGEN-style (gain stall)      | atlas    |  26 |      0.769 |                0     |              0     |        0     |                0     |         0.229 |                  1     |
| fifo       | Confidence stop               | atlas    |  26 |      0.731 |                0     |              0.125 |        0     |                0     |         0.138 |                  0.944 |
| fifo       | Conformal deferral (end only) | atlas    |  26 |      0.615 |                0     |              0     |        0.462 |                0.667 |         0.988 |                  0.167 |
| fifo       | Fixed budget                  | atlas    |  26 |      0.577 |                0     |              0.625 |        0     |                0     |         0.988 |                  0.111 |
| fifo       | RISKSTOP                      | atlas    |  26 |      0.808 |                0     |              0     |        0.115 |                0.333 |         0.081 |                  1     |
| evictguard | BAGEN-style (gain stall)      | cdb      |  58 |      0.431 |                0.315 |              1     |        0     |                0     |         0.177 |                  0.243 |
| evictguard | Confidence stop               | cdb      |  58 |      0.5   |                0.241 |              1     |        0     |                0     |         0.909 |                  0.293 |
| evictguard | Conformal deferral (end only) | cdb      |  58 |      0.259 |                0.111 |              0     |        0.897 |                0.882 |         0.971 |                nan     |
| evictguard | Fixed budget                  | cdb      |  58 |      0.5   |                0.241 |              1     |        0     |                0     |         0.971 |                  0.293 |
| evictguard | RISKSTOP                      | cdb      |  58 |      0.241 |                0.185 |              0     |        0.828 |                0.824 |         0.185 |                nan     |
| fifo       | BAGEN-style (gain stall)      | cdb      |  58 |      0.431 |                0.296 |              1     |        0     |                0     |         0.165 |                  0.211 |
| fifo       | Confidence stop               | cdb      |  58 |      0.586 |                0.185 |              0.5   |        0     |                0     |         0.978 |                  0.136 |
| fifo       | Conformal deferral (end only) | cdb      |  58 |      0.293 |                0.037 |              0     |        0.966 |                1     |         0.978 |                nan     |
| fifo       | Fixed budget                  | cdb      |  58 |      0.586 |                0.185 |              0.5   |        0     |                0     |         0.978 |                  0.136 |
| fifo       | RISKSTOP                      | cdb      |  58 |      0.293 |                0.037 |              0     |        0.966 |                1     |         0.233 |                nan     |
| evictguard | BAGEN-style (gain stall)      | otrf     |  85 |      0.541 |                0.118 |              0.647 |        0     |                0     |         0.173 |                  0.533 |
| evictguard | Confidence stop               | otrf     |  85 |      0.541 |                0.078 |              0.647 |        0     |                0     |         0.788 |                  0.596 |
| evictguard | Conformal deferral (end only) | otrf     |  85 |      0.247 |                0.02  |              0     |        0.906 |                1     |         0.982 |                nan     |
| evictguard | Fixed budget                  | otrf     |  85 |      0.529 |                0.078 |              0.676 |        0     |                0     |         0.982 |                  0.596 |
| evictguard | RISKSTOP                      | otrf     |  85 |      0.247 |                0.098 |              0.059 |        0.8   |                0.786 |         0.191 |                  0     |
| fifo       | BAGEN-style (gain stall)      | otrf     |  85 |      0.459 |                0.216 |              0.735 |        0     |                0     |         0.17  |                  0.55  |
| fifo       | Confidence stop               | otrf     |  85 |      0.482 |                0.275 |              0.588 |        0     |                0     |         0.875 |                  0.378 |
| fifo       | Conformal deferral (end only) | otrf     |  85 |      0.188 |                0.059 |              0     |        0.929 |                0.929 |         0.975 |                  1     |
| fifo       | Fixed budget                  | otrf     |  85 |      0.482 |                0.275 |              0.588 |        0     |                0     |         0.975 |                  0.378 |
| fifo       | RISKSTOP                      | otrf     |  85 |      0.224 |                0.078 |              0.059 |        0.824 |                0.786 |         0.239 |                  0.4   |