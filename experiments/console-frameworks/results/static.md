| candidate | JS gzip (B) | CSS gzip (B) | lockfile packages (runtime) | installed here | node_modules | clean build (s) | same bytes on rebuild | own lines |
|---|---|---|---|---|---|---|---|---|
| baseline (whole console, unminified) | 35946 | 7473 | 0 (0) | 0 | 0 | 0 (none) | yes (no build) | 1878 |
| lit-esbuild | 12432 | 5520 | 29 (2) | 4 | 14M | 0.7 | yes | 254 |
| lit | 12231 | 5573 | 49 (2) | 19 | 68M | 1.3 | yes | 254 |
| preact-esbuild | 14056 | 5520 | 28 (1) | 3 | 13M | 0.7 | yes | 389 |
| preact | 13866 | 5560 | 48 (1) | 18 | 66M | 1.3 | yes | 389 |
| solid-h | 20043 | 5520 | 31 (4) | 6 | 15M | 0.6 | yes | 381 |
| solid | 17482 | 5551 | 106 (4) | 76 | 88M | 2.4 | yes | 363 |
| svelte | 24858 | 5573 | 71 (19) | 41 | 74M | 2.0 | yes | 328 |
| vanilla | 8364 | 5520 | 27 (0) | 2 | 12M | 0.5 | yes | 306 |
| vue | 32219 | 5573 | 67 (23) | 37 | 83M | 1.6 | yes | 410 |
