"""(1) Dikte variant-family test. (2) Known-plaintext attack with the libation formula."""
import re, sys, random, collections, importlib.util, io, contextlib, itertools
src=open(sys.argv[1],encoding='utf-8').read()
SYL=re.compile(r'^(?:[A-Z]{1,3}[₂₃]?|\*\d{2,3})$')
def okw(w): ps=w.split('-'); return len(ps)>=2 and all(SYL.match(x) for x in ps)
INS={}
for m in re.finditer(r'\["([^"]+)",\{(.*?)\n\}\]',src,re.S):
    t=re.search(r'"transliteratedWords":\s*\[(.*?)\]',m.group(2),re.S)
    if t: INS[m.group(1)]=[tuple(w.split('-')) for w in re.findall(r'"((?:[^"\\]|\\.)*)"',t.group(1)) if okw(w)]
la=[w for ws in INS.values() for w in ws]; U=sorted(set(la)); BYL=collections.defaultdict(list)
for w in U: BYL[len(w)].append(w)
spec=importlib.util.spec_from_file_location("p",sys.argv[2]);p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
A_=[tuple(w) for w in p.A]; B_=[tuple(w) for w in p.B]; DISC=[w for w in A_+B_ if '?' not in w]
def prof(seqs):
    c=collections.defaultdict(collections.Counter)
    for w in seqs:
        for i,x in enumerate(w): c[x]['I' if i==0 else 'F' if i==len(w)-1 else 'M']+=1
    return {k:[v[z]/sum(v.values()) for z in 'IMF'] for k,v in c.items()}
PD,PL=prof(DISC),prof(la)
def fp(key): return sum(sum(abs(a-b) for a,b in zip(PD[d],PL[l])) for d,l in key.items())/len(key)
def support(key,exclude):
    vals=set(key.values()); n=0
    for dw in set(DISC):
        if dw in exclude or sum(x in key for x in dw)<2: continue
        for lw in BYL[len(dw)]:
            m,ok={},True
            for d,l in zip(dw,lw):
                if d in key:
                    if key[d]!=l: ok=False;break
                elif d in m:
                    if m[d]!=l: ok=False;break
                elif l in vals or l in m.values(): ok=False;break
                else: m[d]=l
            if ok: n+=1;break
    return n
P1,P2=('07','23','18','24'),('16','23','18','43')
def keyof(w1,w2):
    k={}
    for d,l in list(zip(P1,w1))+list(zip(P2,w2)):
        if k.get(d,l)!=l: return None
        k[d]=l
    return k if len(set(k.values()))==len(k) else None
real=keyof(('JA','DI','KI','TU'),('A','DI','KI','TE'))
rs,rf=support(real,{P1,P2}),fp(real)
# decoys: every Linear A pair of 4-sign words sharing the middle two signs, differing at both ends
fam=collections.defaultdict(list)
for w in BYL[4]: fam[w[1:3]].append(w)
dec=[]
for mid,ws in fam.items():
    for w1,w2 in itertools.permutations(ws,2):
        if w1[0]!=w2[0] and w1[3]!=w2[3] and 'DI' not in mid:
            k=keyof(w1,w2)
            if k: dec.append((support(k,{P1,P2}),fp(k)))
print("== 1. Dikte variant family ==")
print(f"Key: {real}")
print(f"Supporting disc words: {rs} | positional-fit distance: {rf:.2f} (lower = better)")
print(f"Decoy variant families from Linear A: {len(dec)}")
print(f"  p(support >= {rs}) = {sum(s>=rs for s,_ in dec)/len(dec):.3f}")
print(f"  p(fit <= {rf:.2f})   = {sum(f<=rf for _,f in dec)/len(dec):.3f}")
print(f"  p(both)          = {sum(s>=rs and f<=rf for s,f in dec)/len(dec):.3f}")

print("\n== 2. Known-plaintext attack: libation formula ==")
def win_match(pw,dw):
    if [len(x) for x in pw]!=[len(x) for x in dw]: return False
    f,b={},{}
    for a,c in zip(itertools.chain(*pw),itertools.chain(*dw)):
        if f.get(a,c)!=c or b.get(c,a)!=a: return False
        f[a]=c; b[c]=a
    return True
def disc_windows(k):
    for side in (A_,B_):
        for i in range(len(side)-k+1):
            w=side[i:i+k]
            if all('?' not in x for x in w): yield w
FORMULA=['IOZa2','TLZa1','PKZa11','PKZa12','PKZa8','IOZa6','PSZa2','PLZf1']
for k in (2,3):
    fw=[INS[n][i:i+k] for n in FORMULA if n in INS for i in range(len(INS[n])-k+1)]
    hits=[(f,d) for f in fw for d in disc_windows(k) if win_match(f,d)]
    other=[ws[i:i+k] for n,ws in INS.items() if n not in FORMULA for i in range(len(ws)-k+1)]
    rate=lambda W: sum(any(win_match(w,d) for d in disc_windows(k)) for w in W)/max(1,len(W))
    print(f" {k}-word windows: formula {len(fw)}, consistent placements on disc {len(hits)}"
          f" | formula windows that fit: {rate(fw):.1%} vs other Linear A text: {rate(other):.1%}")
    for f,d in hits[:3]: print("   ", ' '.join('-'.join(x) for x in f),' <=> ',' '.join('-'.join(x) for x in d))

print("\n== 1b. Fair null: every family may choose its best disc pair (same selection the real one got) ==")
d4=[w for w in set(DISC) if len(w)==4 and len(set(w))==4]
pairs=[(a,b) for a,b in itertools.permutations(d4,2) if a[1:3]==b[1:3] and a[0]!=b[0] and a[3]!=b[3]]
print(f"Disc pairs of form X-m-n-Y / Z-m-n-W: {len(pairs)}")
def best_over_pairs(w1,w2):
    best=-1
    for a,b in pairs:
        k={}; ok=True
        for d,l in list(zip(a,w1))+list(zip(b,w2)):
            if k.get(d,l)!=l: ok=False;break
            k[d]=l
        if ok and len(set(k.values()))==len(k): best=max(best,support(k,{a,b}))
    return best
allfam=[(w1,w2) for mid,ws in fam.items() for w1,w2 in itertools.permutations(ws,2)
        if w1[0]!=w2[0] and w1[3]!=w2[3]]
scores=[best_over_pairs(*f) for f in allfam]
realb=best_over_pairs(('JA','DI','KI','TU'),('A','DI','KI','TE'))
print(f"Linear A variant families tested: {len(allfam)} | Dikte best: {realb}")
print(f"Families scoring >= Dikte: {sum(s>=realb for s in scores)} -> p = {sum(s>=realb for s in scores)/len(scores):.3f}")
print("Top families:", sorted(((s,'-'.join(a)+'/'+'-'.join(b)) for s,(a,b) in zip(scores,allfam)),reverse=True)[:5])
