## 1 KB requests

| setup | new conn p50 / p99 (ms) | keep-alive p50 / p99 (µs) | req/s, 16 kept conns | req/s, 16 workers, new conn each | p99 at 16 kept conns (ms) |
|---|---|---|---|---|---|
| direct | 1.48 / 4.28 | 125 / 336 | 19660 | 1072 | 2.3 |
| direct-h2 | 1.62 / 4.51 | 181 / 672 | 9890 | 722 | 5.9 |
| mitm-memaudit/unix | 1.75 / 4.55 | 467 / 1298 | 5949 | 1572 | 6.3 |
| mitm-nopool/unix | 4.04 / 6.81 | 2430 / 7199 | 520 | 483 | 72.3 |
| mitm/fwd | 3.18 / 8.65 | 1286 / 2500 | 1167 | 633 | 42.1 |
| mitm/socat | 12.87 / 59.16 | 2132 / 8408 | 730 | 334 | 77.9 |
| mitm/socat-nodelay | 4.27 / 11.76 | 1318 / 2615 | 1354 | 679 | 21.8 |
| mitm/unix | 4.41 / 8.10 | 1318 / 5435 | 930 | 462 | 58.0 |
| pass-h2/unix | 1.88 / 4.16 | 254 / 539 | 12103 | 1070 | 4.4 |
| pass-splice/fwd-splice | 2.67 / 11.68 | 242 / 616 | 5977 | 516 | 7.6 |
| pass-splice/unix | 1.73 / 4.57 | 183 / 462 | 17704 | 843 | 3.8 |
| pass/socat | 43.19 / 45.96 | 269 / 1034 | 9624 | 516 | 4.4 |
| pass/unix | 1.66 / 2.41 | 180 / 447 | 18847 | 1310 | 2.2 |
| sni-splice/tcp | 1.75 / 4.55 | 182 / 596 | 7588 | 1012 | 7.4 |
| sni/tcp | 1.62 / 2.86 | 209 / 331 | 15165 | 1144 | 3.2 |

## New connection, phase by phase (p50, µs)

| setup | connect | CONNECT | TLS handshake | first response | total |
|---|---|---|---|---|---|
| direct | 200 | 0 | 908 | 281 | 1477 |
| direct-h2 | 152 | 0 | 886 | 442 | 1623 |
| mitm-memaudit/unix | 110 | 143 | 807 | 596 | 1745 |
| mitm-nopool/unix | 112 | 168 | 841 | 2599 | 4038 |
| mitm/fwd | 203 | 305 | 937 | 1546 | 3181 |
| mitm/socat | 716 | 1174 | 1251 | 6030 | 12875 |
| mitm/socat-nodelay | 326 | 703 | 944 | 1736 | 4271 |
| mitm/unix | 170 | 156 | 947 | 2419 | 4414 |
| pass-h2/unix | 136 | 137 | 1138 | 444 | 1885 |
| pass-splice/fwd-splice | 351 | 458 | 1229 | 461 | 2675 |
| pass-splice/unix | 121 | 114 | 1072 | 318 | 1733 |
| pass/socat | 494 | 731 | 1336 | 40818 | 43190 |
| pass/unix | 99 | 117 | 1070 | 318 | 1665 |
| sni-splice/tcp | 224 | 0 | 1135 | 319 | 1747 |
| sni/tcp | 148 | 0 | 1109 | 328 | 1623 |

## 100 MB downloads

| setup | MB/s median (min–max) | proxy CPU s/GB | hop CPU s/GB | client CPU s/GB | origin CPU s/GB |
|---|---|---|---|---|---|
| direct | 477 (275–910) | 0.00 | 0.00 | 1.15 | 1.10 |
| direct-h2 | 271 (207–616) | 0.00 | 0.00 | 2.07 | 1.57 |
| mitm-memaudit/unix | 334 (241–482) | 2.37 | 0.00 | 1.32 | 1.00 |
| mitm-nopool/unix | 328 (201–458) | 2.50 | 0.00 | 1.26 | 1.00 |
| mitm/fwd | 197 (117–259) | 2.63 | 1.63 | 1.88 | 1.00 |
| mitm/socat | 230 (159–343) | 2.57 | 0.90 | 1.44 | 1.00 |
| mitm/socat-nodelay | 265 (134–354) | 2.60 | 1.20 | 2.02 | 0.97 |
| mitm/unix | 202 (156–459) | 2.43 | 0.00 | 1.44 | 1.03 |
| pass-h2/unix | 346 (203–509) | 1.03 | 0.00 | 1.87 | 1.60 |
| pass-splice/fwd-splice | 562 (310–802) | 0.23 | 0.30 | 1.30 | 1.13 |
| pass-splice/unix | 523 (400–892) | 0.17 | 0.00 | 1.10 | 1.07 |
| pass/socat | 261 (188–312) | 1.10 | 0.97 | 1.38 | 1.00 |
| pass/unix | 378 (160–705) | 1.07 | 0.00 | 1.44 | 1.03 |
| sni-splice/tcp | 590 (331–829) | 0.23 | 0.00 | 1.33 | 1.17 |
| sni/tcp | 366 (136–705) | 1.43 | 0.00 | 1.52 | 1.10 |

## CPU per 1,000 requests at 16 kept connections (ms)

| setup | proxy, kept | hop, kept | proxy, new conn | hop, new conn |
|---|---|---|---|---|
| direct | 0 | 0 | 0 | 0 |
| direct-h2 | 0 | 0 | 0 | 0 |
| mitm-memaudit/unix | 200 | 0 | 658 | 0 |
| mitm-nopool/unix | 895 | 0 | 1293 | 0 |
| mitm/fwd | 369 | 77 | 833 | 414 |
| mitm/socat | 363 | 115 | 1032 | 1310 |
| mitm/socat-nodelay | 364 | 90 | 858 | 1248 |
| mitm/unix | 360 | 0 | 849 | 0 |
| pass-h2/unix | 32 | 0 | 315 | 0 |
| pass-splice/fwd-splice | 46 | 46 | 694 | 669 |
| pass-splice/unix | 40 | 0 | 611 | 0 |
| pass/socat | 38 | 35 | 456 | 1497 |
| pass/unix | 27 | 0 | 281 | 0 |
| sni-splice/tcp | 48 | 0 | 599 | 0 |
| sni/tcp | 33 | 0 | 315 | 0 |

## 10 MB upload (s, median)

| setup | seconds |
|---|---|
| direct | 0.024 |
| direct-h2 | 0.031 |
| mitm-memaudit/unix | 0.048 |
| mitm-nopool/unix | 0.041 |
| mitm/fwd | 0.063 |
| mitm/socat | 0.078 |
| mitm/socat-nodelay | 0.044 |
| mitm/unix | 0.057 |
| pass-h2/unix | 0.026 |
| pass-splice/fwd-splice | 0.024 |
| pass-splice/unix | 0.019 |
| pass/socat | 0.050 |
| pass/unix | 0.030 |
| sni-splice/tcp | 0.017 |
| sni/tcp | 0.038 |

## Proxy stage timings (p50 / p99 µs, median over rounds)

| setup | stage | n per round | p50 / p99 |
|---|---|---|---|
| mitm-memaudit/unix | audit_emit | 31341 | 64.5 / 2409.6 |
| mitm-memaudit/unix | box_tls_accept | 6462 | 5388.7 / 12302.4 |
| mitm-memaudit/unix | connect_judge_host | 6462 | 0.7 / 2.1 |
| mitm-memaudit/unix | decide | 31341 | 5.7 / 26.7 |
| mitm-memaudit/unix | leaf_server_config | 6462 | 0.4 / 1.3 |
| mitm-memaudit/unix | request_body_buffered | 31341 | 0.9 / 1.7 |
| mitm-memaudit/unix | upstream_response_headers | 31341 | 1106.6 / 3984.4 |
| mitm-nopool/unix | audit_emit | 5268 | 2687.2 / 20396.6 |
| mitm-nopool/unix | box_tls_accept | 2105 | 8346.6 / 25569.1 |
| mitm-nopool/unix | connect_judge_host | 2105 | 1.2 / 3.1 |
| mitm-nopool/unix | decide | 5268 | 6.8 / 46.6 |
| mitm-nopool/unix | leaf_server_config | 2105 | 0.6 / 2.1 |
| mitm-nopool/unix | request_body_buffered | 5268 | 1.3 / 3.8 |
| mitm-nopool/unix | upstream_response_headers | 5268 | 12385.4 / 36420.6 |
| mitm/fwd | audit_emit | 8456 | 2491.5 / 16099.3 |
| mitm/fwd | box_tls_accept | 2705 | 9806.3 / 23596.6 |
| mitm/fwd | connect_judge_host | 2705 | 1.3 / 3.5 |
| mitm/fwd | decide | 8456 | 6.7 / 29.2 |
| mitm/fwd | leaf_server_config | 2705 | 0.7 / 2.1 |
| mitm/fwd | request_body_buffered | 8456 | 1.2 / 2.8 |
| mitm/fwd | upstream_response_headers | 8456 | 3832.4 / 15613.9 |
| mitm/socat | audit_emit | 5509 | 2035.6 / 20720.5 |
| mitm/socat | box_tls_accept | 1508 | 2486.2 / 21318.7 |
| mitm/socat | connect_judge_host | 1508 | 1.4 / 5.0 |
| mitm/socat | decide | 5509 | 6.8 / 38.0 |
| mitm/socat | leaf_server_config | 1508 | 0.9 / 2.7 |
| mitm/socat | request_body_buffered | 5509 | 1.2 / 4.1 |
| mitm/socat | upstream_response_headers | 5509 | 1392.7 / 19177.4 |
| mitm/socat-nodelay | audit_emit | 9513 | 2317.3 / 11665.9 |
| mitm/socat-nodelay | box_tls_accept | 2891 | 6945.3 / 17739.4 |
| mitm/socat-nodelay | connect_judge_host | 2891 | 1.3 / 3.3 |
| mitm/socat-nodelay | decide | 9513 | 6.7 / 23.8 |
| mitm/socat-nodelay | leaf_server_config | 2891 | 0.8 / 2.2 |
| mitm/socat-nodelay | request_body_buffered | 9513 | 1.2 / 2.5 |
| mitm/socat-nodelay | upstream_response_headers | 9513 | 2383.5 / 9238.6 |
| mitm/unix | audit_emit | 6828 | 2374.0 / 25376.5 |
| mitm/unix | box_tls_accept | 2024 | 13374.0 / 42860.1 |
| mitm/unix | connect_judge_host | 2024 | 1.1 / 3.7 |
| mitm/unix | decide | 6828 | 6.6 / 31.7 |
| mitm/unix | leaf_server_config | 2024 | 0.6 / 2.4 |
| mitm/unix | request_body_buffered | 6828 | 1.2 / 4.0 |
| mitm/unix | upstream_response_headers | 6828 | 4839.4 / 24708.2 |
| pass-h2/unix | connect_decide | 4453 | 8.3 / 3469.7 |
| pass-h2/unix | sni_peek_check | 4453 | 1540.3 / 6530.6 |
| pass-h2/unix | upstream_connect | 4453 | 266.2 / 2555.5 |
| pass-splice/fwd-splice | connect_decide | 2236 | 2174.1 / 23037.0 |
| pass-splice/fwd-splice | sni_peek_check | 2236 | 3373.5 / 24229.7 |
| pass-splice/fwd-splice | upstream_connect | 2236 | 129.0 / 7999.4 |
| pass-splice/unix | connect_decide | 3546 | 13.2 / 7275.1 |
| pass-splice/unix | sni_peek_check | 3546 | 1890.9 / 9771.4 |
| pass-splice/unix | upstream_connect | 3546 | 222.3 / 6220.2 |
| pass/socat | connect_decide | 2237 | 17.4 / 2871.1 |
| pass/socat | sni_peek_check | 2237 | 1695.0 / 14099.5 |
| pass/socat | upstream_connect | 2237 | 120.1 / 2250.2 |
| pass/unix | connect_decide | 5413 | 8.3 / 3392.2 |
| pass/unix | sni_peek_check | 5413 | 1307.9 / 6028.2 |
| pass/unix | upstream_connect | 5413 | 239.3 / 2281.0 |
| sni-splice/tcp | sni_peek_check | 4224 | 26.3 / 8998.1 |
| sni-splice/tcp | upstream_connect | 4224 | 345.5 / 6960.5 |
| sni/tcp | sni_peek_check | 4750 | 21.5 / 6434.6 |
| sni/tcp | upstream_connect | 4750 | 359.8 / 4159.3 |

## In-box curl (box.sh): per request ms p50 / p99, downloads MB/s median

| box | leg | new conn total | new conn: until TLS done | keep-alive total | 100 MB MB/s |
|---|---|---|---|---|---|
| runc-direct | direct | 6.41 / 11.87 | 5.80 | 0.21 / 0.36 | 455 |
| runc | local | 6.29 / 11.51 | 5.69 | 2.26 / 4.29 | 443 |
| runc | mitm | 46.92 / 53.62 | 7.12 | 1.43 / 3.12 | 250 |
| runc | mitm-b256k | 9.31 / 18.51 | 6.97 | 1.75 / 5.96 | 235 |
| runc | mitm-nodelay | 9.21 / 22.70 | 7.11 | 1.43 / 4.91 | 172 |
| runc | pass | 11.55 / 54.85 | 7.63 | 0.35 / 2.58 | 305 |
| runc | raw | 46.32 / 53.76 | 6.39 | 0.39 / 0.64 | 247 |
| runc | raw-b256k | 7.22 / 15.56 | 6.31 | 0.34 / 0.92 | 407 |
| runsc | local | 8.97 / 20.37 | 7.74 | 3.31 / 8.14 | 104 |
| runsc | mitm | 21.53 / 44.90 | 18.06 | 3.91 / 12.96 | 14 |
| runsc | mitm-b256k | 26.27 / 59.20 | 21.33 | 1.69 / 5.17 | 170 |
| runsc | mitm-nodelay | 39.21 / 68.18 | 32.44 | 4.36 / 10.30 | 11 |
| runsc | pass | 21.35 / 41.53 | 18.04 | 0.92 / 3.01 | 47 |
| runsc | raw | 16.90 / 35.25 | 14.03 | 0.77 / 1.67 | 46 |
| runsc | raw-b256k | 16.50 / 31.44 | 13.74 | 0.83 / 3.19 | 104 |

