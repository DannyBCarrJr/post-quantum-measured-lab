"""Place-name crib test (Ventris method) with look-elsewhere-safe controls.
For each name: every disc word of identical shape is a candidate slot, either
the bare word or with the 02 / 02-12 'tag' stripped. Each slot yields a partial key;
score = other disc words (>=2 keyed signs) that become real Linear A words.
Best slot score vs best slot score of decoy Linear A words with same shape."""
import re, sys, random, collections, importlib.util, io, contextlib
src=open(sys.argv[1],encoding='utf-8').read(); raw=[]
for arr in re.findall(r'"transliteratedWords":\s*\[(.*?)\]',src,re.S):
    raw+=re.findall(r'"((?:[^"\\]|\\.)*)"',arr)
SYL=re.compile(r'^(?:[A-Z]{1,3}[₂₃]?|\*\d{2,3})$')
la=[tuple(w.split('-')) for w in raw if len(w.split('-'))>=2 and all(SYL.match(x) for x in w.split('-'))]
U=sorted(set(la)); BYL=collections.defaultdict(list)
for w in U: BYL[len(w)].append(w)
spec=importlib.util.spec_from_file_location("p",sys.argv[2]);p=importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
A_=[tuple(w) for w in p.A]; B_=[tuple(w) for w in p.B]
DISC=[w for w in A_+B_ if '?' not in w]
def shape(w): m={}; return tuple(m.setdefault(s,len(m)) for s in w)
def core(w):
    if w[:2]==('02','12'): return w[2:],'02-12 tag'
    if w[0]=='02': return w[1:],'02 tag'
    return w,'bare'
def slots(name):
    out=[]
    for w in set(DISC):
        c,tag=core(w)
        if len(c)==len(name) and shape(c)==shape(name): out.append((w,c,tag))
        if tag!='bare' and shape(w)==shape(name): out.append((w,w,'bare'))
    return out
def match_any(dw,key,vals):
    for lw in BYL[len(dw)]:
        m,ok={},True
        for d,l in zip(dw,lw):
            if d in key:
                if key[d]!=l: ok=False;break
            elif d in m:
                if m[d]!=l: ok=False;break
            elif l in vals or l in m.values(): ok=False;break
            else: m[d]=l
        if ok: return '-'.join(lw)
    return None
def best(name):
    res=[]
    for w,c,tag in slots(name):
        key=dict(zip(c,name)); vals=set(name); hits=[]
        for dw in set(DISC):
            if dw==w or sum(x in key for x in dw)<2: continue
            m=match_any(dw,key,vals)
            if m: hits.append(('-'.join(dw),m))
        res.append((len(hits),'-'.join(w),tag,hits))
    res.sort(key=lambda r:-r[0]); return res
NAMES={'PA-I-TO':'Phaistos','JA-DI-KI-TU':'Dikte (sacred mtn)','SU-KI-RI-TA':'Sybrita'}
PLACES={tuple(n.split('-')) for n in NAMES}
rng=random.Random(11)
refrain_slots={'02-12-31-26','02-27-25-10-23-18','28-01','02-12-27-27-35-37-21','33-23'}
for n,label in NAMES.items():
    name=tuple(n.split('-')); r=best(name); top=r[0][0] if r else 0
    decoys=[w for w in U if len(w)==len(name) and shape(w)==shape(name) and w not in PLACES]
    sample=rng.sample(decoys,min(300,len(decoys)))
    null=[(best(d)[0][0] if best(d) else 0) for d in sample]
    pv=sum(x>=top for x in null)/len(null)
    print(f"\n== {n} ({label}) ==  candidate slots on disc: {len(r)}")
    print(f" best slot: {r[0][1]} [{r[0][2]}] -> {top} supporting words {r[0][3][:4]}")
    print(f" decoys ({len(sample)} same-shape LA words): mean best {sum(null)/len(null):.2f}, p = {pv:.3f}")
    tagged=[x for x in r if x[2]!='bare']; lit=[x for x in r if x[1] in refrain_slots]
    print(f" slots that are 02-tagged: {len(tagged)} | slots inside side-A litany: {[x[1] for x in lit]}")
