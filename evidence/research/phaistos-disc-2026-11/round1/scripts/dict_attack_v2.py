"""v2 CORRECTION (declared after v1, fixes a confound found in v1):
 - count UNIQUE disc words only (scrambling destroys repeats; v1 rewarded repetition)
 - 3 independent runs on the real disc (seeds) vs 12 scrambled
PASS only if the WORST real run beats the BEST scrambled run."""
import sys, random, importlib.util, io, contextlib
spec=importlib.util.spec_from_file_location("d","scripts/dict_attack.py"); d=importlib.util.module_from_spec(spec)
sys.argv=[sys.argv[0]]+sys.argv[1:]
src=open("scripts/dict_attack.py").read().split("rng=random.Random(1700)")[0]
g={}; 
with contextlib.redirect_stdout(io.StringIO()): exec(compile(src,"dict_attack.py","exec"),g)
DISC=list(dict.fromkeys(g['DISC']))            # unique words, order kept
print("unique disc words:",len(DISC))
for name in ('Linear B','Linear A+B'):
    D=g['DICTS'][name]
    real=[len({w for w,_ in g['attack'](DISC,D,random.Random(s))[1]}) for s in (1,2,3)]
    rng=random.Random(99)
    ctrl=[]
    for _ in range(12):
        sd=list(dict.fromkeys(g['scramble'](DISC,rng)))
        ctrl.append(len({w for w,_ in g['attack'](sd,D,rng)[1]}))
    print(f"\n== {name} ==\n real runs (unique hits): {real}\n scrambled: {sorted(ctrl)} mean {sum(ctrl)/12:.1f}")
    print(" verdict:", "PASS" if min(real)>max(ctrl) else "FAIL")
