"""Recon: classify the cipher before attacking it.

Run: python3 -I recon.py
No corpora needed. Every number printed here is quoted in the article.
"""
import collections
import math
import random

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I drops the script dir; disc.py lives beside this file
from disc import SIDE_A, words

W = words()
signs = [s for w in W for s in w]
known = [s for s in signs if s != '?']
c = collections.Counter(known)

print('== Inventory')
print(f'words: {len(W)} (A {len(SIDE_A)}, B {len(W) - len(SIDE_A)})')
print(f'sign tokens: {len(known)} legible + {len(signs) - len(known)} damaged; distinct signs: {len(c)}')
hapax = sorted(k for k, v in c.items() if v == 1)
print(f'signs used once: {len(hapax)} {hapax}')

print('\n== Sign 02')
initial = sum(w[0] == '02' for w in W)
inner = sum('02' in w[1:] for w in W)
print(f'02 occurrences: {c["02"]}; word-initial: {initial}; anywhere else: {inner}')
bare = [i for i, w in enumerate(W) if w == ('13', '01')]
tagged = [i for i, w in enumerate(W) if w == ('02', '12', '13', '01')]
print(f'13-01 bare at {["AB"[i >= 31] + str(i + 1 - 31 * (i >= 31)) for i in bare]}, '
      f'as 02-12-13-01 at {["AB"[i >= 31] + str(i + 1 - 31 * (i >= 31)) for i in tagged]}')

print('\n== Side A refrain')
A = words('A')
ref = ('02', '12', '31', '26')
pos = [i + 1 for i, w in enumerate(A) if w == ref]
print(f'02-12-31-26 at A{pos}')
for i in range(13, 22):
    print(f'  A{i + 1:<2} {"-".join(A[i])}')
stripped = ['-'.join(w[1:] if w[0] == '02' else w) for w in W]
print(f'12-31-26 after stripping a leading 02: {stripped.count("12-31-26")} times')

print('\n== Script type: distinct signs expected in a 241-sign text (Zipf usage, s = 1)')
rng = random.Random(20261125)
N_TOK = len(known)


def trial(n):
    weights = [1 / (r + 1) for r in range(n)]
    draw = collections.Counter(rng.choices(range(n), weights, k=N_TOK))
    return len(draw), sum(v == 1 for v in draw.values())


TRIALS = 2000
for n, label in [(25, 'alphabet'), (60, 'syllabary'), (90, 'syllabary'), (200, 'logo-syllabic'), (800, 'logographic')]:
    res = [trial(n) for _ in range(TRIALS)]
    d = sorted(r[0] for r in res)
    h = sum(r[1] for r in res) / TRIALS
    print(f'  {label:<13} {n:>4} signs: distinct mean {sum(d) / TRIALS:5.1f} '
          f'(middle 95%: {d[int(.025 * TRIALS)]} to {d[int(.975 * TRIALS)]}); signs used once, mean {h:4.1f}')

fits = []
for n in range(45, 201, 5):
    res = [trial(n) for _ in range(400)]
    if sum(abs(r[0] - 45) <= 3 and abs(r[1] - 9) <= 3 for r in res) / 400 >= 0.05:
        fits.append(n)
print(f'inventories where >= 5% of trials land within 3 of both 45 distinct and 9 once-only: '
      f'{fits[0] if fits else None} to {fits[-1] if fits else None}')

print('\n== Unicity distance, illustrative')
hk = (math.lgamma(61) - math.lgamma(16)) / math.log(2)
print(f'H(K) for 45 signs mapped one-to-one into 60 syllables: log2(60!/15!) = {hk:.1f} bits')
print(f'U at an assumed 2.5 bits/syllable redundancy: {hk / 2.5:.0f} signs (disc has {N_TOK})')
