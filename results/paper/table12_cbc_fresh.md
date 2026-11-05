Fresh test: ATLASv2 Carbon Black EDR (16 scenarios, REAPr process labels), cold start

|                                                    |   attack_process_coverage |   noise_share |   supporting_action_recall |
|:---------------------------------------------------|--------------------------:|--------------:|---------------------------:|
| ('background-flood', 0.01, 'evictguard_online_v2') |                     0.665 |         0.141 |                      0.034 |
| ('background-flood', 0.01, 'evictguard_v1')        |                     0.521 |         0.008 |                      0.015 |
| ('background-flood', 0.01, 'evictguard_v2')        |                     0.716 |         0.046 |                      0.035 |
| ('background-flood', 0.01, 'evictguard_v3')        |                     0.728 |         0.096 |                      0.037 |
| ('background-flood', 0.01, 'evictguard_v4')        |                     0.719 |         0.061 |                      0.045 |
| ('background-flood', 0.01, 'fifo')                 |                     0.092 |         0.253 |                      0.001 |
| ('background-flood', 0.01, 'nodoze')               |                     0.115 |         0     |                      0.065 |
| ('background-flood', 0.01, 'random')               |                     0.529 |         0.269 |                      0.019 |
| ('background-flood', 0.01, 'rare_action')          |                     0.533 |         0     |                      0.04  |
| ('background-flood', 0.01, 'recency_dedup')        |                     0.153 |         0.246 |                      0.002 |
| ('background-flood', 0.05, 'evictguard_online_v2') |                     0.727 |         0.114 |                      0.195 |
| ('background-flood', 0.05, 'evictguard_v1')        |                     0.802 |         0.126 |                      0.064 |
| ('background-flood', 0.05, 'evictguard_v2')        |                     0.9   |         0.096 |                      0.201 |
| ('background-flood', 0.05, 'evictguard_v3')        |                     0.918 |         0.118 |                      0.184 |
| ('background-flood', 0.05, 'evictguard_v4')        |                     0.879 |         0.119 |                      0.176 |
| ('background-flood', 0.05, 'fifo')                 |                     0.398 |         0.271 |                      0.03  |
| ('background-flood', 0.05, 'nodoze')               |                     0.122 |         0     |                      0.296 |
| ('background-flood', 0.05, 'random')               |                     0.8   |         0.305 |                      0.089 |
| ('background-flood', 0.05, 'rare_action')          |                     0.689 |         0     |                      0.198 |
| ('background-flood', 0.05, 'recency_dedup')        |                     0.392 |         0.302 |                      0.074 |
| ('none', 0.01, 'evictguard_online_v2')             |                     0.628 |         0     |                      0.027 |
| ('none', 0.01, 'evictguard_v1')                    |                     0.486 |         0     |                      0.01  |
| ('none', 0.01, 'evictguard_v2')                    |                     0.649 |         0     |                      0.025 |
| ('none', 0.01, 'evictguard_v3')                    |                     0.649 |         0     |                      0.031 |
| ('none', 0.01, 'evictguard_v4')                    |                     0.639 |         0     |                      0.033 |
| ('none', 0.01, 'fifo')                             |                     0.068 |         0     |                      0.001 |
| ('none', 0.01, 'nodoze')                           |                     0.116 |         0     |                      0.045 |
| ('none', 0.01, 'random')                           |                     0.5   |         0     |                      0.018 |
| ('none', 0.01, 'rare_action')                      |                     0.466 |         0     |                      0.018 |
| ('none', 0.01, 'recency_dedup')                    |                     0.097 |         0     |                      0.001 |
| ('none', 0.05, 'evictguard_online_v2')             |                     0.721 |         0     |                      0.093 |
| ('none', 0.05, 'evictguard_v1')                    |                     0.736 |         0     |                      0.049 |
| ('none', 0.05, 'evictguard_v2')                    |                     0.85  |         0     |                      0.086 |
| ('none', 0.05, 'evictguard_v3')                    |                     0.87  |         0     |                      0.083 |
| ('none', 0.05, 'evictguard_v4')                    |                     0.847 |         0     |                      0.092 |
| ('none', 0.05, 'fifo')                             |                     0.36  |         0     |                      0.025 |
| ('none', 0.05, 'nodoze')                           |                     0.119 |         0     |                      0.22  |
| ('none', 0.05, 'random')                           |                     0.743 |         0     |                      0.086 |
| ('none', 0.05, 'rare_action')                      |                     0.59  |         0     |                      0.088 |
| ('none', 0.05, 'recency_dedup')                    |                     0.388 |         0     |                      0.065 |