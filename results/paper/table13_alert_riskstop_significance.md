RISKSTOP (LTT) minus baseline, per-investigation expected cost (negative = RISKSTOP cheaper), bootstrap 95% CI

| memory     | vs                               |   n |   mean_cost_diff | CI95                                           |   riskstop_better_share |   worse_share |
|:-----------|:---------------------------------|----:|-----------------:|:-----------------------------------------------|------------------------:|--------------:|
| evictguard | BAGEN-style (gain stall)         | 371 |           -0.051 | (-0.28687836927223714, 0.1721142183288409)     |                   0.642 |         0.35  |
| evictguard | Confidence stop                  | 371 |           -0.079 | (-0.35331199460916446, 0.1634113881401617)     |                   0.07  |         0.496 |
| evictguard | Conformal deferral (end only)    | 371 |           -0.366 | (-0.5408389487870621, -0.19775943396226422)    |                   0.698 |         0.299 |
| evictguard | Fixed budget                     | 371 |           -0.465 | (-0.7057395552560647, -0.2568547843665769)     |                   0.647 |         0.353 |
| evictguard | RISKSTOP - no query value        | 371 |           -0.05  | (-0.10574292452830186, -0.0018143530997304662) |                   0.237 |         0.1   |
| evictguard | RISKSTOP - no residual risk      | 371 |            0     | (0.0, 0.0)                                     |                   0     |         0     |
| evictguard | RISKSTOP - uncalibrated defaults | 371 |           -0.184 | (-0.4610158355795148, 0.06462432614555255)     |                   0.199 |         0.469 |
| fifo       | BAGEN-style (gain stall)         | 371 |           -0.261 | (-0.5257749326145552, -0.012858827493261511)   |                   0.582 |         0.412 |
| fifo       | Confidence stop                  | 371 |           -0.153 | (-0.42602762803234506, 0.08753537735849058)    |                   0.102 |         0.496 |
| fifo       | Conformal deferral (end only)    | 371 |           -0.505 | (-0.6612702156334231, -0.37032513477088963)    |                   0.784 |         0.205 |
| fifo       | Fixed budget                     | 371 |           -0.763 | (-1.0455087601078168, -0.5102240566037736)     |                   0.588 |         0.412 |
| fifo       | RISKSTOP - no query value        | 371 |           -0.134 | (-0.2745367250673854, -0.0059097035040432105)  |                   0.294 |         0.189 |
| fifo       | RISKSTOP - no residual risk      | 371 |            0     | (0.0, 0.0)                                     |                   0     |         0     |
| fifo       | RISKSTOP - uncalibrated defaults | 371 |           -0.292 | (-0.5790431266846361, -0.0369710242587602)     |                   0.208 |         0.461 |