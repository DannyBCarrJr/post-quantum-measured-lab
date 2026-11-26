import importlib.util,sys,io,contextlib
spec=importlib.util.spec_from_file_location("p","phaistos.py");p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
for name,side in (("A",p.A),("B",p.B)):
    j=['-'.join(w) for w in side]
    print(f"\nSide {name}: {len(j)} words, 02-prefixed: {sum(w[0]=='02' for w in side)}")
    print(" ".join(f"[{i}]{w}" for i,w in enumerate(j)))
    pos=[i for i,w in enumerate(j) if w=='02-12-31-26']
    if pos: print(" refrain 02-12-31-26 at", pos, "gaps", [b-a for a,b in zip(pos,pos[1:])])
# shared vocabulary between sides
sa={'-'.join(w) for w in p.A}; sb={'-'.join(w) for w in p.B}
print("\nWords on both sides:", sa&sb)
# stems shared across sides after stripping 02-12 / 02
def core(w): 
    w=w[2:] if w[:2]==['02','12'] else (w[1:] if w[0]=='02' else w); return '-'.join(w)
ca={core(w) for w in p.A}; cb={core(w) for w in p.B}
print("Shared cores after stripping prefix:", ca&cb)
