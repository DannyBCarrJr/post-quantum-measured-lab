import importlib.util,io,contextlib,random,collections
spec=importlib.util.spec_from_file_location("p","phaistos.py");p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
W=p.words
def shape(w):
    m={};return tuple(m.setdefault(s,len(m)) for s in w)
target=shape(['a','sa','sa','ra','me'])
print("Words matching A-SA-SA-RA-ME shape:",['-'.join(w) for w in W if shape(w)==target])
crib={'29':'A','24':'SA','20':'RA','35':'ME'}
for s in crib:
    pos=collections.Counter('init' if w[0]==s else 'final' if w[-1]==s else 'mid' for w in W for x in w if x==s)
    print(f"sign {s}={crib[s]}: {dict(pos)}")
print("\nPartial substitution:")
print("  ".join('-'.join(crib.get(x,x) for x in w) for w in W))
# null test: shuffle signs, how often does an a-b-b-c-d word AND a second occurrence of its b-c pair appear?
toks=[x for w in W for x in w]; lens=[len(w) for w in W]; hits=0;N=5000
random.seed(7)
for _ in range(N):
    random.shuffle(toks); it=iter(toks); ws=[[next(it) for _ in range(l)] for l in lens]
    cand=[w for w in ws if shape(w)==target]
    for c in cand:
        pair=(c[2],c[3]); n=sum(1 for w in ws for i in range(len(w)-1) if (w[i],w[i+1])==pair)
        if n>=2: hits+=1;break
print(f"\nNull model: random text produces that coincidence {hits/N:.1%} of the time")
