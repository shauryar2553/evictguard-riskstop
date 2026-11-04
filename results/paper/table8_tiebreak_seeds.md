Anomaly baselines with 5 random tie-break seeds (no noise): mean recall and mean per-episode SD across seeds

|                                                  |   mean_recall |   mean_seed_sd |
|:-------------------------------------------------|--------------:|---------------:|
| ('ATLASv2 h1 (dev)', 256.0, 'nodoze')            |         0.001 |          0.001 |
| ('ATLASv2 h1 (dev)', 256.0, 'rare_action')       |         0.009 |          0.009 |
| ('ATLASv2 h1 (dev)', 1024.0, 'nodoze')           |         0.002 |          0.002 |
| ('ATLASv2 h1 (dev)', 1024.0, 'rare_action')      |         0.03  |          0.014 |
| ('ATLASv2 h1 (dev)', 4096.0, 'nodoze')           |         0.016 |          0.002 |
| ('ATLASv2 h1 (dev)', 4096.0, 'rare_action')      |         0.125 |          0.015 |
| ('ATLASv2 h2 (held-out)', 256.0, 'nodoze')       |         0.001 |          0.003 |
| ('ATLASv2 h2 (held-out)', 256.0, 'rare_action')  |         0.009 |          0.007 |
| ('ATLASv2 h2 (held-out)', 1024.0, 'nodoze')      |         0.007 |          0.005 |
| ('ATLASv2 h2 (held-out)', 1024.0, 'rare_action') |         0.047 |          0.019 |
| ('ATLASv2 h2 (held-out)', 4096.0, 'nodoze')      |         0.022 |          0.002 |
| ('ATLASv2 h2 (held-out)', 4096.0, 'rare_action') |         0.17  |          0.012 |
| ('otrf_native_test', 0.01, 'nodoze')             |         0.06  |          0.037 |
| ('otrf_native_test', 0.01, 'rare_action')        |         0.06  |          0.082 |
| ('otrf_native_test', 0.05, 'nodoze')             |         0.28  |          0.057 |
| ('otrf_native_test', 0.05, 'rare_action')        |         0.327 |          0.23  |
| ('otrf_native_val', 0.01, 'nodoze')              |         0.109 |          0.005 |
| ('otrf_native_val', 0.01, 'rare_action')         |         0.07  |          0.098 |
| ('otrf_native_val', 0.05, 'nodoze')              |         0.225 |          0.018 |
| ('otrf_native_val', 0.05, 'rare_action')         |         0.376 |          0.274 |