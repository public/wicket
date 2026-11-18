# Splits a script's items into N CI parts by their times (ci/kani.sh's and ci/tla.sh's --shard).
#
#   awk -v n=N [-v dflt=SECONDS] [-v summary=1] -f ci/shard.awk TIMES ITEMS
#
# TIMES holds "name seconds" lines, as the scripts' "… shard I/N times" annotations print them
# ("name 24 s" or "name 24s"); ITEMS one item name a line, in the script's order. Prints
# item<TAB>part<TAB>seconds for each item in that order, parts 1..N: longest first (a stable sort,
# so ties stay in input order), each to the part with the least so far (ties to the lowest part).
# An item missing from TIMES counts as dflt seconds (default 30). With summary=1, prints instead
# each part's expected seconds and its items.
#
# Every part runs the same split from the same inputs, so every item is in exactly one part. The
# times only balance the parts: a stale or missing one can slow a part, never drop an item.
FNR == NR { t[$1] = $2 + 0; next }
{ name[m++] = $0 }
END {
  if (dflt == "") dflt = 30
  for (i = 0; i < m; i++) { o[i] = i; s[i] = (name[i] in t) ? t[name[i]] : dflt }
  for (i = 1; i < m; i++)
    for (j = i; j > 0 && s[o[j]] > s[o[j - 1]]; j--) { x = o[j]; o[j] = o[j - 1]; o[j - 1] = x }
  for (p = 1; p <= n; p++) load[p] = 0
  for (k = 0; k < m; k++) {
    i = o[k]; best = 1
    for (p = 2; p <= n; p++) if (load[p] < load[best]) best = p
    part[i] = best; load[best] += s[i]
  }
  if (summary) {
    for (p = 1; p <= n; p++) {
      c = 0; l = ""
      for (i = 0; i < m; i++) if (part[i] == p) { c++; l = l "  " name[i] " " s[i] " s\n" }
      printf "part %d: %d s, %d items\n%s", p, load[p], c, l
    }
  } else {
    for (i = 0; i < m; i++) printf "%s\t%d\t%d\n", name[i], part[i], s[i]
  }
}
