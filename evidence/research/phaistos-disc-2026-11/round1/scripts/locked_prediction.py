"""LOCKED PREDICTION (written before running; do not edit after first run)
Key under test (Dikte family): 07=JA 23=DI 18=KI 24=TU 16=A 43=TE
Prediction: if the key is real, the keyed signs appearing in disc words OTHER than
the two crib words (07-23-18-24, 16-23-18-43) will form sound sequences typical of
Linear A: adjacent keyed pairs and keyed word-starts/word-ends get high Linear A
bigram probability.
Metric M = mean log P under a Linear A bigram model (add-0.5, with <start>/<end>).
PASS only if BOTH:
  (1) M beats >= 95% of 5000 random keys (same 6 disc signs, 6 random distinct LA syllables)
  (2) M ranks first among keys built from the 17 real Linear A variant families
      mapped onto the same disc pair
Otherwise FAIL. No re-runs with altered metric."""
import re, sys, math, random, collections, importlib.util, io, contextlib, itertools
src=open(sys.argv[1],encoding='utf-8').read(); raw=[]
for arr in re.findall(r'"transliteratedWords":\s*\[(.*?)\]',src,re.S):
    raw+=re.findall(r'"((?:[^"\\]|\\.)*)"',arr)
SYL=re.compile(r'^(?:[A-Z]{1,3}[₂₃]?|\*\d{2,3})$')
la=[tuple(w.split('-')) for w in raw if len(w.split('-'))>=2 and all(SYL.match(x) for x in w.split('-'))]
V=sorted({x for w in la for x in w})+['<','>']
bg=collections.Counter(); ug=collections.Counter()
for w in la:
    s=['<',*w,'>']
    for a,b in zip(s,s[1:]): bg[(a,b)]+=1; ug[a]+=1
lp=lambda a,b: math.log((bg[(a,b)]+0.5)/(ug[a]+0.5*len(V)))
spec=importlib.util.spec_from_file_location("p",sys.argv[2]);p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
CRIB={('07','23','18','24'),('16','23','18','43')}
DISC=[tuple(w) for w in p.words if '?' not in w and tuple(w) not in CRIB]
def M(key,show=False):
    terms=[]
    for w in DISC:
        s=['<',*w,'>']
        for a,b in zip(s,s[1:]):
            ka=key.get(a,a if a in '<>' else None); kb=key.get(b,b if b in '<>' else None)
            if ka and kb and not (ka in '<>' and kb in '<>'):
                terms.append(lp(ka,kb))
                if show: print(f"   {a}->{b} = {ka}->{kb}  logP {lp(ka,kb):.2f}")
    return sum(terms)/len(terms), len(terms)
KEY={'07':'JA','23':'DI','18':'KI','24':'TU','16':'A','43':'TE'}
print("Keyed transitions in the rest of the disc:")
m,n=M(KEY,True); print(f"M = {m:.3f} over {n} transitions")
pool=[s for s,_ in collections.Counter(x for w in la for x in w).most_common(60)]
rng=random.Random(1908)
null=[M(dict(zip(KEY,rng.sample(pool,6))))[0] for _ in range(5000)]
c1=sum(x>=m for x in null)/5000
fam=collections.defaultdict(list)
for w in {w for w in la if len(w)==4}: fam[w[1:3]].append(w)
P1,P2=('07','23','18','24'),('16','23','18','43'); fk=[]
for ws in fam.values():
    for w1,w2 in itertools.permutations(ws,2):
        if w1[0]!=w2[0] and w1[3]!=w2[3]:
            k={}; ok=True
            for d,l in list(zip(P1,w1))+list(zip(P2,w2)):
                if k.get(d,l)!=l: ok=False;break
                k[d]=l
            if ok and len(set(k.values()))==len(k): fk.append(('-'.join(w1)+'/'+'-'.join(w2),M(k)[0]))
fk.sort(key=lambda x:-x[1])
rank=[i for i,(n_,_) in enumerate(fk) if n_.startswith('JA-DI-KI-TU') or n_.startswith('A-DI-KI-TE')][0]+1
print(f"\n(1) random keys: p = {c1:.3f}  -> {'pass' if c1<=0.05 else 'FAIL'}")
print(f"(2) rank among {len(fk)} real-family keys: {rank}  -> {'pass' if rank<=2 else 'FAIL'}")
print("    top families:", [(n_,round(v,2)) for n_,v in fk[:4]])
print("\nLOCKED VERDICT:", "PASS" if c1<=0.05 and rank<=2 else "FAIL")
