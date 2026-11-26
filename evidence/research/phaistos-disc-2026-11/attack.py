"""Dictionary attack on the Phaistos Disc, with scrambled-disc controls.

Run: python3 -I attack.py LinearAInscriptions.js LinearBInscriptions.js lexicon.js

The attacker treats the disc as a simple substitution cipher: each of its signs stands for
one syllable, no two signs for the same one. A hill climber searches for the key that turns
the most disc words into real words from a dictionary (Linear A, or Linear B's Greek).
A leading sign 02 is stripped first, on the theory that it is a silent tag, and words
holding the damaged sign are skipped.

Control: the identical search on scrambled discs. Same signs, same word lengths, order
shuffled. If the real disc scores no better than its scrambled twins, the attack found noise.

PASS RULE, written before the first run on 2026-11-25 and not edited after:
  An attack passes only if, under the v2 score (unique words matched), the real disc's
  score beats the HIGHEST of its 12 scrambled controls on all three real-disc seeds.
  Anything less is a fail.

Two scores are printed. v1 counts word tokens, so a repeated disc word counts every time it
appears. v2 counts unique words. Scrambling destroys repeats, so v1 is rigged in the real
disc's favor; it is reported to show how much the rigging is worth, never to decide a pass.

POST-HOC CHECK, added after the first run and labeled as such in the output. The first run
showed the scramble also tilts v2 the other way: breaking repeats gives a scrambled disc
about 60 unique words to match against the real disc's 52. So the run is repeated against a
repeat-preserving scramble (shuffle signs across the unique words, then restore each word's
repeat count). It cannot change the locked verdict above; it checks whether the fail was an
artifact of the control.
"""
import collections
import random
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I drops the script dir; disc.py lives beside this file
from disc import linear_a_words, linear_b_words, words

RESTARTS, ITERS, CONTROLS, SEEDS = 4, 12000, 12, 3


def disc_words():
    out = []
    for w in words():
        if '?' in w:
            continue
        w = w[1:] if w[0] == '02' else w
        if len(w) >= 2:
            out.append(w)
    return out


def scrambled(ws, rng):
    pool = [s for w in ws for s in w]
    rng.shuffle(pool)
    it = iter(pool)
    return [tuple(next(it) for _ in w) for w in ws]


def scrambled_keep_repeats(ws, rng):
    uniq = list(dict.fromkeys(ws))
    new = dict(zip(uniq, scrambled(uniq, rng)))
    return [new[w] for w in ws]


def climb(ws, dictionary, inventory, rng, reverse=False):
    if reverse:
        ws = [w[::-1] for w in ws]
    mult = collections.Counter(ws)
    uniq = list(mult)
    signs = sorted({s for w in uniq for s in w})
    touch = collections.defaultdict(list)
    for i, w in enumerate(uniq):
        for s in set(w):
            touch[s].append(i)
    best = (-1, -1, [])
    for _ in range(RESTARTS):
        vals = rng.sample(inventory, len(signs))
        key = dict(zip(signs, vals))
        owner = {v: s for s, v in key.items()}
        hit = [tuple(key[s] for s in w) in dictionary for w in uniq]
        score = sum(hit)
        for _ in range(ITERS):
            s = rng.choice(signs)
            y = rng.choice(inventory)
            old = key[s]
            if y == old:
                continue
            t = owner.get(y)
            key[s] = y
            if t is not None:
                key[t] = old
            affected = set(touch[s]) | (set(touch[t]) if t is not None else set())
            delta = 0
            new = {}
            for i in affected:
                h = tuple(key[x] for x in uniq[i]) in dictionary
                new[i] = h
                delta += h - hit[i]
            if delta >= 0:
                for i, h in new.items():
                    hit[i] = h
                score += delta
                owner[y] = s
                if t is not None:
                    owner[old] = t
                else:
                    owner.pop(old, None)
            else:
                key[s] = old
                if t is not None:
                    key[t] = y
        v1 = sum(mult[uniq[i]] for i in range(len(uniq)) if hit[i])
        if score > best[0]:
            matched = ['-'.join(key[x] for x in uniq[i]) + ' <- ' + '-'.join(uniq[i]) for i in range(len(uniq)) if hit[i]]
            best = (score, v1, matched)
    return best


def run(name, dictionary, rng):
    inv_count = collections.Counter(s for w in sorted(dictionary) for s in w)  # sorted: set order varies with hash seed
    inventory = [s for s, _ in sorted(inv_count.items(), key=lambda kv: (-kv[1], kv[0]))[:90]]
    ws = disc_words()
    print(f'\n== {name}: {len(dictionary)} dictionary words, {len(inventory)}-syllable inventory, '
          f'{len(set(ws))} unique disc words ({len(ws)} tokens)')
    verdicts = []
    for reverse in (False, True):
        real = [climb(ws, dictionary, inventory, random.Random(rng.random()), reverse) for _ in range(SEEDS)]
        ctrl = [climb(scrambled(ws, random.Random(rng.random())), dictionary, inventory,
                      random.Random(rng.random()), reverse) for _ in range(CONTROLS)]
        r2, c2 = [r[0] for r in real], sorted(c[0] for c in ctrl)
        r1, c1 = [r[1] for r in real], sorted(c[1] for c in ctrl)
        ok = all(x > max(c2) for x in r2)
        verdicts.append(ok)
        label = 'reversed' if reverse else 'as transcribed'
        print(f'  [{label}] v2 unique: real {r2} | controls {c2[0]} to {c2[-1]} (mean {sum(c2) / len(c2):.1f}) '
              f'-> {"PASS" if ok else "FAIL"}')
        print(f'  [{label}] v1 tokens: real {r1} | controls {c1[0]} to {c1[-1]} '
              f'-> {"would pass" if all(x > max(c1) for x in r1) else "would fail"} under the rigged score')
        top = max(real, key=lambda r: r[0])[2]
        print(f'  [{label}] best real-disc key reads: {", ".join(sorted(top, key=len, reverse=True)[:6])}')
        ctop = max(ctrl, key=lambda r: r[0])[2]
        long_c = [m for c in ctrl for m in c[2] if m.split(' <- ')[0].count('-') >= 2]
        print(f'  [{label}] best scrambled key reads: {", ".join(sorted(ctop, key=len, reverse=True)[:6])}')
        print(f'  [{label}] three-plus-syllable real words found on scrambled discs: {len(long_c)} across {CONTROLS} controls; '
              f'on the real disc: {sum(1 for r in real for m in r[2] if m.split(" <- ")[0].count("-") >= 2)} across {SEEDS} seeds')
        fair = sorted(climb(scrambled_keep_repeats(ws, random.Random(rng.random())), dictionary, inventory,
                            random.Random(rng.random()), reverse)[0] for _ in range(CONTROLS))
        print(f'  [{label}] POST-HOC, repeat-preserving controls, v2: real {r2} | controls {fair[0]} to {fair[-1]} '
              f'(mean {sum(fair) / len(fair):.1f}) -> real beats every control on all seeds: '
              f'{"yes" if all(x > fair[-1] for x in r2) else "no"}')
    return verdicts


if __name__ == '__main__':
    la_path, lb_path, lex_path = sys.argv[1:4]
    rng = random.Random(20261125)
    la = set(linear_a_words(la_path))
    lb = linear_b_words(lb_path, lex_path)
    out = run('Linear A dictionary', la, rng) + run('Linear B dictionary (Greek)', lb, rng)
    print(f'\nattacks passed: {sum(out)} of {len(out)}')
