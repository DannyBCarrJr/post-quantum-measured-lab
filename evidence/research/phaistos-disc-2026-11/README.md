# Evidence: "The cipher that outlived its key"

Reproducible backing for the article's Verified claims about the Phaistos Disc. Not
post-quantum, and not epigraphy. It is a cryptanalysis exercise with controls, kept here
because this repo is where the studio's measured claims live.

Two independent harnesses ran against the same transcription and corpora on the same day.
Round one (`round1/`) is the original eleven-script kit behind the six-attack table. The
second harness (this folder's top level) was written afterwards to check that the
dictionary result was not an artifact of one optimizer or one tokenizer.

## Files
- `disc.py` holds the disc transcription and reads the two corpora. The `.js` corpus files are parsed as text and never executed.
- `recon.py` prints the inventory, the sign 02 tests, the Side A refrain positions, the script-type simulation, and the unicity-distance arithmetic. It needs no corpora.
- `attack.py` runs the dictionary attack against Linear A and Linear B dictionaries, both reading directions, with scrambled-disc controls. The pass rule is in its docstring and was written before the first run.
- `OUTPUT.txt` is the captured run, 2026-11-25.
- `round1/` holds the first-round kit and its own `OUTPUT.txt`: `phaistos.py` (recon and the inline transcription), `litany.py`, `crib.py`, and `scripts/` (`la_test.py`, `fingerprint.py`, `fullkey.py`, `placenames.py`, `dikte_kpa.py`, `locked_prediction.py`, `dict_attack.py`, `dict_attack_v2.py`). Run from `round1/` as `python3 -I scripts/<name>.py LinearAInscriptions.js phaistos.py`, adding `LinearBInscriptions.js lexicon.js` before `phaistos.py` for the two dictionary scripts. `fullkey.py` needs numpy and scipy; the rest are standard library.

## Run it
```
git clone https://github.com/mwenge/lineara.xyz
git clone https://github.com/mwenge/linearb.xyz
python3 -I recon.py
python3 -I attack.py lineara.xyz/LinearAInscriptions.js linearb.xyz/LinearBInscriptions.js linearb.xyz/lexicon.js
```
Standard library only. Tested on Python 3.14.4; older versions were not tried. The attack takes about 20 seconds on a laptop.
Output is deterministic: the seed is fixed and nothing depends on hash order, checked by
running under two different `PYTHONHASHSEED` values and comparing byte for byte.

## Source data
- Disc: Marianna P. Ridderstad's 2010 numeric transcription in Evans' sign numbering, as published at https://omnika.org/texts/919. 61 words, 241 legible signs plus one damaged.
- Linear A: lineara.xyz at commit `9c81beba669a4ffec3f5b29d4e7748d02c060eff`.
- Linear B: linearb.xyz at commit `84e0b00ec00292e7afd4f88315dd715b11666efb`, corpus plus lexicon.

## Definitions that affect a number
- **Dictionary word**: a transliterated word of two or more syllabic signs. Linear A gives 782 unique words. Linear B gives 4,997 unique words, the union of corpus and lexicon. Single-sign words, numerals, and logograms are excluded. A different tokenizer gives different counts, and the article quotes these.
- **Disc word**: a leading sign 02 is stripped (the silent-tag hypothesis), words holding the damaged sign are skipped, and words left with fewer than two signs are dropped. That leaves 60 tokens and 52 unique words.
- **Key**: one-to-one, disc sign to syllable, drawn from the 90 most frequent syllables of the dictionary in use (Linear A has only 62).
- **v1 and v2 scores**: v1 counts matched tokens, so a repeated word counts every time. v2 counts matched unique words. Only v2 decides a pass.
- **Repeat-preserving control**: post-hoc, and labeled so in the output. Added after the first run showed the plain scramble breaks repeats and hands controls extra targets.

## Known quirks
- `round1/litany.py` prints zero-based word indexes, so its `[15, 18, 21]` is A16, A19, and A22 in the conventional numbering. `recon.py` prints the conventional form.
- `round1/scripts/placenames.py` breaks ties between equally good slots by set order, which varies with Python's hash seed. A rerun can name a different tied slot. Its counts and p-values do not change; checked by diffing two full runs on 2026-11-25.
- The second harness tokenizes the corpora more strictly than round one (782 and 4,997 words against 896 and 5,049), on purpose, so the two do not share a tokenizer.
