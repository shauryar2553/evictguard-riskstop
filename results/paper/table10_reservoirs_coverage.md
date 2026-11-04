Stratified reservoirs: recall vs coverage (held-out, no noise)

|                                                               |   core_action_recall |   attack_process_coverage |   stratum_coverage |   supporting_action_recall |
|:--------------------------------------------------------------|---------------------:|--------------------------:|-------------------:|---------------------------:|
| ('ATLASv2 h2 (held-out)', 256.0, 'evictguard_online')         |                0.962 |                     0.596 |              0.904 |                      0.008 |
| ('ATLASv2 h2 (held-out)', 256.0, 'evictguard_online_v2')      |                0.962 |                     0.596 |              0.845 |                      0.009 |
| ('ATLASv2 h2 (held-out)', 256.0, 'evictguard_v3')             |                0.971 |                     0.637 |              0.836 |                      0.01  |
| ('ATLASv2 h2 (held-out)', 256.0, 'online-protected_only')     |                0.962 |                     0.5   |              0.098 |                      0.011 |
| ('ATLASv2 h2 (held-out)', 256.0, 'online_v2-protected_only')  |                0.962 |                     0.5   |              0.098 |                      0.011 |
| ('ATLASv2 h2 (held-out)', 1024.0, 'evictguard_online')        |                0.973 |                     0.548 |              0.907 |                      0.052 |
| ('ATLASv2 h2 (held-out)', 1024.0, 'evictguard_online_v2')     |                0.973 |                     0.548 |              0.907 |                      0.052 |
| ('ATLASv2 h2 (held-out)', 1024.0, 'evictguard_v3')            |                0.985 |                     0.688 |              1     |                      0.05  |
| ('ATLASv2 h2 (held-out)', 1024.0, 'online-protected_only')    |                0.973 |                     0.5   |              0.098 |                      0.054 |
| ('ATLASv2 h2 (held-out)', 1024.0, 'online_v2-protected_only') |                0.973 |                     0.5   |              0.098 |                      0.054 |
| ('otrf_native_val', 0.01, 'evictguard_online')                |                0.362 |                     0.801 |              0.457 |                      0.077 |
| ('otrf_native_val', 0.01, 'evictguard_online_v2')             |                0.534 |                     0.832 |              0.367 |                      0.134 |
| ('otrf_native_val', 0.01, 'evictguard_v2')                    |                0.303 |                     0.801 |              0.362 |                      0.106 |
| ('otrf_native_val', 0.01, 'evictguard_v3')                    |                0.339 |                     0.759 |              0.378 |                      0.106 |
| ('otrf_native_val', 0.01, 'online_v2-protected_only')         |                0.557 |                     0.764 |              0.217 |                      0.113 |
| ('otrf_native_val', 0.05, 'evictguard_online')                |                0.851 |                     0.923 |              0.791 |                      0.218 |
| ('otrf_native_val', 0.05, 'evictguard_online_v2')             |                0.898 |                     0.917 |              0.717 |                      0.386 |
| ('otrf_native_val', 0.05, 'evictguard_v2')                    |                0.889 |                     0.931 |              0.83  |                      0.361 |
| ('otrf_native_val', 0.05, 'evictguard_v3')                    |                0.882 |                     0.937 |              0.832 |                      0.397 |
| ('otrf_native_val', 0.05, 'online_v2-protected_only')         |                0.856 |                     0.895 |              0.404 |                      0.356 |