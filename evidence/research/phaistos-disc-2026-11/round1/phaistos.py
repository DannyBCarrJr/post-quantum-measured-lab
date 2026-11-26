"""Phaistos Disc cryptanalysis toolkit.
Source: Ridderstad (2010) numeric transcription, Evans numbering (01-45).
'?' = damaged sign. Trailing '/' = incised virgule (stroke) under last sign.
"""
import math, random, collections, itertools

SIDE_A = """02-12-13-01-18/ 24-40-12 29-45-07/ 29-29-34 02-12-04-40-33 27-45-07-12 27-44-08
02-12-06-18-? 31-26-35 02-12-41-19-35 01-41-40-07 02-12-32-23-38/ 39-11 02-27-25-10-23-18 28-01/
02-12-31-26/ 02-12-27-27-35-37-21 33-23 02-12-31-26/ 02-27-25-10-23-18 28-01/ 02-12-31-26/
02-12-27-14-32-18-27 06-18-17-19 31-26-12 02-12-13-01 23-19-35/ 10-03-38 02-12-27-27-35-37-21 13-01 10-03-38"""
SIDE_B = """02-12-22-40-07 27-45-07-35 02-37-23-05/ 22-25-27 33-24-20-12 16-23-18-43/ 13-01-39-33 15-07-13-01-18
22-37-42-25 07-24-40-35 02-26-36-40 27-25-38-01 29-24-24-20-35 16-14-18 29-33-01 06-35-32-39-33
02-09-27-01 29-36-07-08/ 29-08-13 29-45-07/ 22-29-36-07-08/ 27-34-23-25 07-18-35 07-45-07/
07-23-18-24 22-29-36-07-08/ 09-30-39-18-07 02-06-35-23-07 29-34-23-25 45-07/"""

def parse(text):
    return [[s for s in g.rstrip('/').split('-')] for g in text.split()]

A, B = parse(SIDE_A), parse(SIDE_B)
words = A + B
tokens = [s for w in words for s in w if s != '?']
freq = collections.Counter(tokens)

print(f"Words: {len(words)} (A={len(A)}, B={len(B)})")
print(f"Legible sign tokens: {len(tokens)}  |  distinct signs: {len(freq)}")
print(f"Word length: min {min(map(len,words))}, max {max(map(len,words))}, "
      f"mean {sum(map(len,words))/len(words):.2f}")

# --- 1. Inventory size: how big is the full script? (Chao1 + simulation) ---
f1 = sum(1 for c in freq.values() if c == 1)
f2 = sum(1 for c in freq.values() if c == 2)
chao1 = len(freq) + (f1*f1)/(2*f2) if f2 else float('nan')
print(f"\nHapax (seen once): {f1}  |  seen twice: {f2}")
print(f"Chao1 estimated total sign inventory: ~{chao1:.0f}")

def sim_distinct(inventory, n=len(tokens), trials=2000, zipf=1.0):
    w = [1/(r**zipf) for r in range(1, inventory+1)]
    return sum(len(set(random.choices(range(inventory), w, k=n)))
               for _ in range(trials)) / trials
random.seed(1)
print("\nExpected distinct signs in a 241-token sample (Zipf-ish usage):")
for label, inv in [("alphabet", 25), ("syllabary", 60), ("syllabary", 90),
                   ("logo-syllabic", 200), ("logographic", 800)]:
    print(f"  {label:14s} inventory {inv:4d} -> ~{sim_distinct(inv):.0f} distinct")

# --- 2. Positional behaviour ---
initial = collections.Counter(w[0] for w in words)
final = collections.Counter(w[-1] for w in words if w[-1] != '?')
print("\nSign 02 (plumed head): total", freq['02'],
      "| word-initial", initial['02'])
print("Bigram 02-12 opens", sum(1 for w in words if w[:2]==['02','12']), "words")
print("Most common word-final signs:", final.most_common(5))

# --- 3. Repeated words / shared endings ---
wc = collections.Counter('-'.join(w) for w in words)
print("\nRepeated words:", [(k,v) for k,v in wc.items() if v>1])
endings = collections.Counter('-'.join(w[-2:]) for w in words if len(w)>=3)
print("Repeated 2-sign endings:", [(k,v) for k,v in endings.items() if v>1])

# Same 'stem' with and without the 02-12 prefix -> prefix is a morpheme?
stems = {'-'.join(w) for w in words}
pref = [('-'.join(w), '-'.join(w[2:])) for w in words
        if w[:2]==['02','12'] and '-'.join(w[2:]) in stems]
print("Words that also appear WITHOUT the 02-12 prefix:", pref)

# --- 4. Entropy ---
H = -sum(c/len(tokens)*math.log2(c/len(tokens)) for c in freq.values())
print(f"\nUnigram entropy: {H:.2f} bits/sign (max for 45 signs = {math.log2(45):.2f})")

print("\nTop 10 signs:", freq.most_common(10))
