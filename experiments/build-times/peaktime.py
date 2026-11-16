"""GNU time's `-f '%e %M' -o FILE CMD...` for hosts without it (#219): wall seconds and the peak
resident set (KiB) of the largest process the command ran, waited for. Run with `python3 -I`."""
import resource, subprocess, sys, time

args = sys.argv[1:]
out = None
while args and args[0] in ("-f", "-o"):
    if args[0] == "-o":
        out = args[1]
    args = args[2:]
t = time.monotonic()
st = subprocess.call(args)
secs = time.monotonic() - t
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
line = f"{secs:.2f} {peak}\n"
if out:
    open(out, "w").write(line)
else:
    sys.stderr.write(line)
sys.exit(st)
