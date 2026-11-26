"""Full-key test: build a 45-sign key for the Phaistos Disc from positional
fingerprints + frequency rank vs Linear A, via optimal assignment (Hungarian).
Pre-registered metrics:
  M1 exact hits  = disc words that become a real Linear A word
  M2 bigram LL   = mean log-prob per sign transition under a Linear A bigram model
Controls: (a) random keys, (b) SAME fitting procedure run on scrambled disc text.
Both reading directions."""
import re, sys, math, random, collections, importlib.util, io, contextlib
import numpy as np
from scipy.optimize import linear_sum_assignment
src=open(sys.argv[1],encoding='utf-8').read()
raw=[]
for arr in re.findall(r'"transliteratedWords":\s*\[(.*?)\]',src,re.S):
    raw+=re.findall(r'"((?:[^"\\]|\\.)*)"',arr)
SYL=re.compile(r'^(?:[A-Z]{1,3}[₂₃]?|\*\d{2,3})$')
la=[tuple(w.split('-')) for w in raw if len(w.split('-'))>=2 and all(SYL.match(x) for x in w.split('-'))]
LAW=set(la)
spec=importlib.util.spec_from_file_location("p",sys.argv[2]);p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
DISC=[tuple(w) for w in p.words if '?' not in w]

sf=collections.Counter(x for w in la for x in w)
POOL=[s for s,_ in sf.most_common(60)]
# bigram model with word-boundary tokens, add-0.5 smoothing
V=POOL+['<','>']; bg=collections.Counter(); ug=collections.Counter()
for w in la:
    seq=['<']+[x if x in POOL else None for x in w]+['>']
    for a,b in zip(seq,seq[1:]):
        if a and b: bg[(a,b)]+=1; ug[a]+=1
def lp(a,b): return math.log((bg[(a,b)]+0.5)/(ug[a]+0.5*len(V)))

def prof(seqs):
    c=collections.defaultdict(collections.Counter)
    for w in seqs:
        for i,x in enumerate(w): c[x]['I' if i==0 else 'F' if i==len(w)-1 else 'M']+=1
    return {k:np.array([v['I'],v['M'],v['F']])/sum(v.values()) for k,v in c.items()}
PL=prof(la); LA_RANK={s:i/len(POOL) for i,s in enumerate(POOL)}

def fit(disc):
    PD=prof(disc); df=collections.Counter(x for w in disc for x in w)
    signs=[s for s,_ in df.most_common()]; DR={s:i/len(signs) for i,s in enumerate(signs)}
    C=np.array([[np.abs(PD[d]-PL[l]).sum()+abs(DR[d]-LA_RANK[l]) for l in POOL] for d in signs])
    r,c=linear_sum_assignment(C)
    return {signs[i]:POOL[j] for i,j in zip(r,c)}

def score(disc,key):
    hits=sum(1 for w in disc if tuple(key[x] for x in w) in LAW)
    ll=[];  
    for w in disc:
        seq=['<']+[key[x] for x in w]+['>']
        ll+=[lp(a,b) for a,b in zip(seq,seq[1:])]
    return hits, sum(ll)/len(ll)

def scramble(disc,rng):
    t=[x for w in disc for x in w]; rng.shuffle(t); it=iter(t)
    return [tuple(next(it) for _ in w) for w in disc]

rng=random.Random(2026); N=1000
for label,disc in (("Standard (outside-in per Ridderstad)",DISC),
                   ("Reversed reading direction",[tuple(reversed(w)) for w in reversed(DISC)])):
    key=fit(disc); h,ll=score(disc,key)
    signs=sorted({x for w in disc for x in w})
    rnd=[score(disc,dict(zip(signs,rng.sample(POOL,len(signs))))) for _ in range(N)]
    scr=[]
    for _ in range(N):
        s=scramble(disc,rng); scr.append(score(s,fit(s)))
    p=lambda arr,i,v: sum(x[i]>=v for x in arr)/len(arr)
    print(f"\n== {label} ==")
    print(f" fitted key: exact hits {h}, bigram LL {ll:.3f}")
    print(f" vs random keys      : hits mean {np.mean([x[0] for x in rnd]):.2f} p={p(rnd,0,h):.3f} | LL mean {np.mean([x[1] for x in rnd]):.3f} p={p(rnd,1,ll):.3f}")
    print(f" vs fitted-on-scramble: hits mean {np.mean([x[0] for x in scr]):.2f} p={p(scr,0,h):.3f} | LL mean {np.mean([x[1] for x in scr]):.3f} p={p(scr,1,ll):.3f}")
    if label.startswith("Standard"):
        print(" crib signs got:", {s:key[s] for s in ('29','24','20','35')})
        print(" exact hits:", ['-'.join(w)+'='+'-'.join(key[x] for x in w) for w in disc if tuple(key[x] for x in w) in LAW])
        print(" sample reading (side A, first 8):", "  ".join('-'.join(key[x] for x in w) for w in disc[:8]))
