| candidate | first card (ms) | FCP (ms) | heap (KB) | elements | script per poll (ms) | cards kept | errors |
|---|---|---|---|---|---|---|---|
| baseline | 1853 | 684 | 2240 | 1012 | 2.2 | yes | none |
| lit | 1152 | 1072 | 2137 | 322 | 2.3 | yes | none |
| lit-esbuild | 1176 | 1104 | 2137 | 320 | 2.4 | yes | none |
| preact | 1201 | 716 | 2178 | 315 | 8.9 | yes | none |
| preact-esbuild | 1233 | 708 | 2179 | 315 | 9.6 | yes | none |
| solid | 1294 | 796 | 2805 | 483 | 2.1 | yes | none |
| solid-h | 1349 | 808 | 2978 | 483 | 2.1 | yes | none |
| svelte | 1684 | 900 | 2533 | 317 | 10.4 | yes | none |
| vanilla | 1143 | 616 | 1946 | 333 | 1.9 | yes | none |
| vue | 1654 | 976 | 2658 | 318 | 2.2 | yes | none |

A later run (same profile) of the two no-build variants, with Lit and plain JS again beside them:

| candidate | first card (ms) | FCP (ms) | heap (KB) | elements | script per poll (ms) | cards kept | errors |
|---|---|---|---|---|---|---|---|
| lit-nobuild | 1288 | 1212 | 2158 | 327 | 2.2 | yes | none |
| vanilla-nobuild | 1163 | 724 | 1955 | 334 | 2.3 | yes | none |
| lit | 1159 | 1060 | 2137 | 322 | 2.3 | yes | none |
| vanilla | 1199 | 628 | 1946 | 333 | 2.2 | yes | none |
