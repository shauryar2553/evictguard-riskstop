Core action recall: streaming (online) vs batch EVICTGuard; reservoir ablation

|                                                     |   evictguard_online |   evictguard_v2 |   online-protected_only |
|:----------------------------------------------------|--------------------:|----------------:|------------------------:|
| ('atlas_h1 (dev)', 'background-flood', 256.0)       |               0.79  |           0.552 |                   0.754 |
| ('atlas_h1 (dev)', 'background-flood', 1024.0)      |               0.835 |           0.823 |                   0.818 |
| ('atlas_h1 (dev)', 'none', 256.0)                   |               0.79  |           0.55  |                   0.754 |
| ('atlas_h1 (dev)', 'none', 1024.0)                  |               0.835 |           0.821 |                   0.818 |
| ('atlas_h2 (held-out)', 'background-flood', 256.0)  |               0.962 |           0.79  |                   0.962 |
| ('atlas_h2 (held-out)', 'background-flood', 1024.0) |               0.973 |           0.973 |                   0.973 |
| ('atlas_h2 (held-out)', 'none', 256.0)              |               0.962 |           0.79  |                   0.962 |
| ('atlas_h2 (held-out)', 'none', 1024.0)             |               0.973 |           0.973 |                   0.973 |
| ('otrf_native_test', 'background-flood', 0.01)      |               0.529 |           0.608 |                   0.529 |
| ('otrf_native_test', 'background-flood', 0.05)      |               0.843 |           0.926 |                   0.824 |
| ('otrf_native_test', 'none', 0.01)                  |               0.48  |           0.578 |                   0.5   |
| ('otrf_native_test', 'none', 0.05)                  |               0.799 |           0.873 |                   0.775 |
| ('otrf_native_train', 'background-flood', 0.01)     |               0.454 |           0.55  |                   0.461 |
| ('otrf_native_train', 'background-flood', 0.05)     |               0.796 |           0.832 |                   0.784 |
| ('otrf_native_train', 'none', 0.01)                 |               0.331 |           0.436 |                   0.396 |
| ('otrf_native_train', 'none', 0.05)                 |               0.723 |           0.745 |                   0.712 |