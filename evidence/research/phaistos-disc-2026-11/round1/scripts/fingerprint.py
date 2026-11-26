import re, sys, random, collections, importlib.util, io, contextlib, math
src = open(sys.argv[1], encoding='utf-8').read()
words=[]
for arr in re.findall(r'"transliteratedWords":\s*\[(.*?)\]', src, re.S):
    words += re.findall(r'"((?:[^"\\]|\\.)*)"', arr)
SYL=re.compile(r'^(?:[A-Z]{1,3}[₂₃]?|\*\d{2,3})$')
la=[tuple(w.split('-')) for w in words if len(w.split('-'))>=2 and all(SYL.match(x) for x in w.split('-'))]
spec=importlib.util.spec_from_file_location("p",sys.argv[2]);p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
disc=[tuple(w) for w in p.words if '?' not in w]
def prof(seqs):
    c=collections.defaultdict(lambda: collections.Counter())
    for w in seqs:
        for i,x in enumerate(w): c[x]['I' if i==0 else 'F' if i==len(w)-1 else 'M']+=1
    return {k:(v['I']/sum(v.values()),v['M']/sum(v.values()),v['F']/sum(v.values()),sum(v.values())) for k,v in c.items()}
PD,PL=prof(disc),prof(la)
def dist(d,l): return sum(abs(a-b) for a,b in zip(PD[d][:3],PL[l][:3]))
KEY={'29':'A','24':'SA','20':'RA','35':'ME'}
real=sum(dist(d,l) for d,l in KEY.items())
pool=[s for s,_ in collections.Counter(x for w in la for x in w).most_common(60)]
random.seed(3); N=20000
null=[sum(dist(d,l) for d,l in zip(KEY,random.sample(pool,4))) for _ in range(N)]
print(f"Fingerprint distance, crib key: {real:.2f} | random keys mean {sum(null)/N:.2f} | p = {sum(x<=real for x in null)/N:.3f}")
# A and ME only (the two with decent sample size)
r2=dist('29','A')+dist('35','ME'); n2=[dist('29',a)+dist('35',b) for a,b in (random.sample(pool,2) for _ in range(N))]
print(f"A + ME only: {r2:.2f} | p = {sum(x<=r2 for x in n2)/N:.3f}")
