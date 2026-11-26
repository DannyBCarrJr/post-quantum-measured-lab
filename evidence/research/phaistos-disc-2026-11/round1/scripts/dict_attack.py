"""DICTIONARY ATTACK on the Phaistos Disc: design locked before first run.
Dictionaries: LA (Linear A words), LB (Linear B words: corpus + lexicon), LA+LB (union).
Disc prep: leading sign 02 treated as a silent tag (supported finding) and stripped;
           damaged word dropped.
Search: simulated annealing over injective keys (45 disc signs -> dictionary syllables),
        objective F = 5*exact + bigram, where
          exact  = disc words (>=3 signs after stripping) that become a dictionary word
          bigram = within-word adjacent pairs that occur in the dictionary
        best of 4 restarts x 30k steps.
Control: the IDENTICAL attack on 12 scrambled discs (same signs, same word lengths).
Primary result: exact hits, real vs scrambled. PASS only if real > every scrambled run."""
import re, sys, math, random, collections, importlib.util, io, contextlib
def subs(x): return x.replace('2','₂').replace('3','₃')
la_src=open(sys.argv[1],encoding='utf-8').read(); lb_src=open(sys.argv[2],encoding='utf-8').read()
lex_src=open(sys.argv[3],encoding='utf-8').read()
SYL=re.compile(r'^(?:[A-Z]{1,3}[₂₃]?|\*\d{2,3})$')
def harvest(src,field,upper=False):
    out=[]
    for arr in re.findall(r'"%s":\s*\[(.*?)\]'%field,src,re.S):
        for w in re.findall(r'"((?:[^"\\]|\\.)*)"',arr):
            w=subs(w.upper()) if upper else w
            ps=w.split('-')
            if len(ps)>=2 and all(SYL.match(p) for p in ps): out.append(tuple(ps))
    return out
LA=set(harvest(la_src,'transliteratedWords'))
LB=set(harvest(lb_src,'transliteratedWords',True))
for t in re.findall(r'"transcription":\s*"([^"]+)"',lex_src):
    ps=subs(t.upper()).split('-')
    if len(ps)>=2 and all(SYL.match(p) for p in ps): LB.add(tuple(ps))
DICTS={'Linear A':LA,'Linear B':LB,'Linear A+B':LA|LB}
print({k:len(v) for k,v in DICTS.items()}, "| shared LA∩LB words:", len(LA&LB))
spec=importlib.util.spec_from_file_location("p",sys.argv[4]);p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
def prep(ws):
    out=[]
    for w in ws:
        w=tuple(w)
        if '?' in w: continue
        if w[0]=='02': w=w[1:]
        if len(w)>=2: out.append(w)
    return out
DISC=prep(p.words)

def attack(disc,D,rng,restarts=4,steps=30000):
    BG={(w[i],w[i+1]) for w in D for i in range(len(w)-1)}
    pool=sorted({s for w in D for s in w})
    signs=sorted({s for w in disc for s in w})
    idx=collections.defaultdict(list)
    for i,w in enumerate(disc):
        for s in set(w): idx[s].append(i)
    def wscore(w,k):
        m=tuple(k[s] for s in w)
        e=5 if (len(w)>=3 and m in D) else 0
        return e+sum((m[i],m[i+1]) in BG for i in range(len(m)-1))
    best=(-1,None)
    for _ in range(restarts):
        k=dict(zip(signs,rng.sample(pool,len(signs)))); used=set(k.values())
        ws=[wscore(w,k) for w in disc]; F=sum(ws); bF,bk=F,dict(k)
        for t in range(steps):
            T=2.0*(1-t/steps)+0.05
            a=rng.choice(signs)
            if rng.random()<0.5:
                b=rng.choice(signs); 
                if a==b: continue
                k[a],k[b]=k[b],k[a]; aff=set(idx[a])|set(idx[b]); undo=('s',a,b)
            else:
                free=[x for x in rng.sample(pool,8) if x not in used]
                if not free: continue
                old=k[a]; new=free[0]; k[a]=new; used.discard(old); used.add(new); aff=set(idx[a]); undo=('r',a,old,new)
            delta=0; newv={}
            for i in aff: newv[i]=wscore(disc[i],k); delta+=newv[i]-ws[i]
            if delta>=0 or rng.random()<math.exp(delta/T):
                for i,v in newv.items(): ws[i]=v
                F+=delta
                if F>bF: bF,bk=F,dict(k)
            else:
                if undo[0]=='s': k[a],k[b]=k[b],k[a]
                else: k[a]=undo[2]; used.discard(undo[3]); used.add(undo[2])
        if bF>best[0]: best=(bF,bk)
    k=best[1]
    exact=[(w,tuple(k[s] for s in w)) for w in disc if len(w)>=3 and tuple(k[s] for s in w) in D]
    return best[0],exact,k

def scramble(disc,rng):
    t=[s for w in disc for s in w]; rng.shuffle(t); it=iter(t)
    return [tuple(next(it) for _ in w) for w in disc]
rng=random.Random(1700)
for name,D in DICTS.items():
    F,ex,k=attack(DISC,D,rng)
    ctrl=[len(attack(scramble(DISC,rng),D,rng)[1]) for _ in range(12)]
    verdict='PASS' if len(ex)>max(ctrl) else 'FAIL'
    print(f"\n== {name} dictionary ==")
    print(f" real disc: exact hits {len(ex)} (objective {F})")
    print(f" scrambled discs: exact hits {sorted(ctrl)}  mean {sum(ctrl)/len(ctrl):.1f}")
    print(f" verdict: {verdict}")
    for w,m in ex[:8]: print("   ",'-'.join(w),'=','-'.join(m))
