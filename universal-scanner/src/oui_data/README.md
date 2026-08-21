# Embedded OUI database

`compact.txt.gz` is the IEEE base-16 OUI feed compressed to `HEX\tVendor` lines
(~407 KB, 39,982 entries at last refresh). It is compiled into the binary via
`include_bytes!` and is the last-resort data source for MAC vendor annotation
(lookup order in `src/oui.rs`: system `ieee-data` package → `uscan update-oui`
user cache → this embedded database).

## Refreshing

One-off maintenance, run from the repository root:

```bash
python3 - <<'PY'
import gzip, re, urllib.request
req = urllib.request.Request("https://standards-oui.ieee.org/oui/oui.txt",
                             headers={"User-Agent": "Mozilla/5.0"})  # IEEE 418s the default UA
out = [f"{m.group(1)}\t{m.group(2)}"
       for m in map(lambda l: re.match(r'^([0-9A-F]{6})\s+\(base 16\)\s*(.+?)\s*$', l.decode()),
                    urllib.request.urlopen(req))]
open("universal-scanner/src/oui_data/compact.txt.gz", "wb").write(gzip.compress("\n".join(out).encode(), 9))
PY
```

Then rebuild; `uscan selftest` is unaffected, but ARP vendor annotation picks up
the new entries on the next run.
