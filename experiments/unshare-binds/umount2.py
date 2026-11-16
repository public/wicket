import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
for p, flags in [(b"/wicket/ca", 0), (b"/wicket/ca", 2), (b"/etc/hosts", 0), (b"/etc/hosts", 2)]:
    r = libc.umount2(p, flags)
    print(p.decode(), "umount2 flags", flags, "->", "OK" if r == 0 else os.strerror(ctypes.get_errno()))
    if r == 0:
        print("  now:", os.listdir(p) if os.path.isdir(p) else open(p).read()[:60])
