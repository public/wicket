| candidate | first card, phone (ms) | range of 7 | first paint, phone (ms) | script per poll, phone (ms) | JS heap (KB) | elements | first card, desktop (ms) | JS gzip (B) | CSS gzip (B) | npm packages (shipped) | node_modules | clean build (s) | Node needed to build | size (nodes) | branches | worst unit | writes by hand | DOM calls |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain JS, esbuild | 1009 | 1004–1036 | 572 | 0.7 | 1946 | 333 | 102 | 8364 | 5520 | 27 (0) | 12M | 0.5 | yes | 4439 | 223 | 37 | 35 | 39 |
| Preact, esbuild | 1013 | 1003–1031 | 652 | 2.7 | 2179 | 315 | 105 | 14056 | 5520 | 28 (1) | 13M | 0.7 | yes | 3932 | 189 | 37 | 16 | 0 |
| Preact, Vite | 1016 | 1001–1029 | 648 | 2.9 | 2162 | 315 | 111 | 13866 | 5560 | 48 (1) | 66M | 1.3 | yes | 3932 | 189 | 37 | 16 | 0 |
| Lit (lit-html), esbuild | 1020 | 1014–1034 | 940 | 0.8 | 2137 | 320 | 106 | 12432 | 5520 | 29 (2) | 14M | 0.7 | yes | 3644 | 188 | 34 | 18 | 2 |
| Lit (lit-html), Vite | 1023 | 1015–1041 | 932 | 0.7 | 2137 | 322 | 95 | 12231 | 5573 | 49 (2) | 68M | 1.3 | yes | 3644 | 188 | 34 | 18 | 2 |
| plain JS, no build | 1024 | 1014–1043 | 664 | 0.7 | 1955 | 334 | 95 | 11637 | 7288 | 0 (0) | 0 | 0 (none) | no | 4439 | 223 | 37 | 35 | 39 |
| Solid, Vite (Babel) | 1061 | 1044–1516 | 724 | 0.8 | 2805 | 483 | 118 | 17482 | 5551 | 106 (4) | 88M | 2.4 | yes | 3692 | 171 | 28 | 8 | 3 |
| Lit (lit-html), no build (4 files committed) | 1071 | 1042–1079 | 1048 | 0.7 | 2159 | 327 | 95 | 16392 | 7288 | 0 (1) | 0 | 0 (none) | no | 3644 | 188 | 34 | 18 | 2 |
| Solid, esbuild (no Babel) | 1516 | 1084–1524 | 740 | 0.8 | 2982 | 483 | 116 | 20043 | 5520 | 31 (4) | 15M | 0.6 | yes | 3692 | 171 | 28 | 8 | 3 |
| today's console on main (reference) | 1530 | 1508–1552 | 436 | 0.8 | 2061 | 569 | 109 | 25581 | 3114 | 0 (0) | 0 | 0 (none) | no | – | – | – | – | – |
