import re, sys, json, random, collections, importlib.util, io, contextlib
corpus_path, disc_path = sys.argv[1], sys.argv[2]
src = open(corpus_path, encoding='utf-8').read()
# pull every transliteratedWords array as plain strings (data only, nothing executed)
words = []
for arr in re.findall(r'"transliteratedWords":\s*\[(.*?)\]', src, re.S):
    words += re.findall(r'"((?:[^"\\]|\\.)*)"', arr)
SYL = re.compile(r'^(?:[A-Z]{1,3}[₂₃]?|\*\d{2,3})$')
la = []
for w in words:
    parts = w.split('-')
    if len(parts) >= 2 and all(SYL.match(p) for p in parts):
        la.append(tuple(parts))
uniq = sorted(set(la))
print(f"Linear A syllabic word tokens: {len(la)} | unique words (2+ signs): {len(uniq)}")
print("Crib source present:", [ '-'.join(w) for w in uniq if 'SA-SA-RA' in '-'.join(w)])

spec = importlib.util.spec_from_file_location("p", disc_path); p = importlib.util.module_from_spec(spec)
with contextlib.redirect_stdout(io.StringIO()): spec.loader.exec_module(p)
disc = [tuple(w) for w in p.words if '?' not in w]
CRIB_WORD = ('29','24','24','20','35')
test_words = [w for w in disc if w != CRIB_WORD]          # exclude circular source word
by_len = collections.defaultdict(list)
for w in uniq: by_len[len(w)].append(w)

def matches(dw, key):
    out = []
    known_vals = set(key.values())
    for lw in by_len[len(dw)]:
        m, used, ok = {}, set(), True
        for d, l in zip(dw, lw):
            if d in key:
                if key[d] != l: ok = False; break
            else:
                if d in m:
                    if m[d] != l: ok = False; break
                elif l in used or l in known_vals: ok = False; break
                else: m[d] = l; used.add(l)
        if ok: out.append(lw)
    return out

def score(key, verbose=False):
    hits = 0; detail = []
    for dw in set(test_words):
        if sum(d in key for d in dw) < 2: continue      # need 2+ fixed signs
        ms = matches(dw, key)
        if ms:
            hits += 1; detail.append(('-'.join(dw), ['-'.join(x) for x in ms[:4]]))
    return (hits, detail) if verbose else hits

KEY = {'29':'A','24':'SA','20':'RA','35':'ME'}
eligible = [w for w in set(test_words) if sum(d in KEY for d in w) >= 2]
h, det = score(KEY, True)
print(f"\nPRE-REGISTERED KEY {KEY}")
print(f"Disc words testable (2+ fixed signs, crib word excluded): {len(eligible)}")
print(f"Words producing a real Linear A word: {h}")
for d, m in det: print("   ", d, "->", m)

random.seed(42)
syl_freq = collections.Counter(s for w in la for s in w)
pool = [s for s, _ in syl_freq.most_common(60)]
N = 5000
# Null 1: same disc signs, random Linear A syllables
n1 = [score(dict(zip(KEY, random.sample(pool, 4)))) for _ in range(N)]
# Null 2: same syllables, random disc signs (any of the 45)
signs = sorted({s for w in disc for s in w})
n2 = [score(dict(zip(random.sample(signs, 4), KEY.values()))) for _ in range(N)]
for name, n in (("random syllables", n1), ("random disc signs", n2)):
    pv = sum(x >= h for x in n) / N
    print(f"Null ({name}): mean {sum(n)/N:.2f} hits, p(>= {h}) = {pv:.3f}")

# Look-elsewhere: how easy is it to find SOME crib?
def shape(w):
    m = {}; return tuple(m.setdefault(s, len(m)) for s in w)
disc_shapes = collections.Counter(shape(w) for w in disc)
rep = [w for w in uniq if len(w) >= 4 and len(set(w)) < len(w)]
fit = [w for w in rep if disc_shapes[shape(w)] == 1]
print(f"\nLook-elsewhere: {len(rep)} Linear A words (4+ signs) contain a repeat;")
print(f"  {len(fit)} of them ({len(fit)/max(1,len(rep)):.0%}) have exactly one disc word of identical shape")

# Positional fingerprint: do the syllables behave in Linear A like their disc signs do on the disc?
def prof(seqs, s):
    c = collections.Counter('I' if w[0]==s else 'F' if w[-1]==s else 'M' for w in seqs for x in w if x==s)
    t = sum(c.values()) or 1
    return {k: round(c[k]/t, 2) for k in 'IMF'}, t
print("\nPositional fingerprint (Initial/Medial/Final share):")
for d, l in KEY.items():
    (pd, td), (pl, tl) = prof(disc, d), prof(la, l)
    print(f"  disc {d} (n={td}) {pd}   vs   LA {l} (n={tl}) {pl}")
