"""Shared loader for the Phaistos Disc transcription and the two Aegean corpora.

Disc text: Marianna P. Ridderstad's 2010 numeric transcription (Evans sign numbers 01 to 45),
as published at https://omnika.org/texts/919. Words are listed A1 to A31 and B1 to B30 in the
conventional order (right to left, rim to center). '?' marks the one damaged sign (A8).

Corpora: github.com/mwenge/lineara.xyz (LinearAInscriptions.js) and
github.com/mwenge/linearb.xyz (LinearBInscriptions.js, lexicon.js). The .js files are read
as text and never executed.
"""
import json
import re

# Ridderstad 2010, appendix 2, as transcribed on OMNIKA. A trailing '/' in the source marks
# the oblique stroke under a word's last sign; it is dropped here because no test uses it.
SIDE_A = """02-12-13-01-18 24-40-12 29-45-07 29-29-34 02-12-04-40-33 27-45-07-12 27-44-08
02-12-06-18-? 31-26-35 02-12-41-19-35 01-41-40-07 02-12-32-23-38 39-11 02-27-25-10-23-18
28-01 02-12-31-26 02-12-27-27-35-37-21 33-23 02-12-31-26 02-27-25-10-23-18 28-01 02-12-31-26
02-12-27-14-32-18-27 06-18-17-19 31-26-12 02-12-13-01 23-19-35 10-03-38 02-12-27-27-35-37-21
13-01 10-03-38""".split()
SIDE_B = """02-12-22-40-07 27-45-07-35 02-37-23-05 22-25-27 33-24-20-12 16-23-18-43 13-01-39-33
15-07-13-01-18 22-37-42-25 07-24-40-35 02-26-36-40 27-25-38-01 29-24-24-20-35 16-14-18 29-33-01
06-35-32-39-33 02-09-27-01 29-36-07-08 29-08-13 29-45-07 22-29-36-07-08 27-34-23-25 07-18-35
07-45-07 07-23-18-24 22-29-36-07-08 09-30-39-18-07 02-06-35-23-07 29-34-23-25 45-07""".split()

assert len(SIDE_A) == 31 and len(SIDE_B) == 30


def words(side=None):
    """Disc words as tuples of sign numbers."""
    src = SIDE_A if side == 'A' else SIDE_B if side == 'B' else SIDE_A + SIDE_B
    return [tuple(w.split('-')) for w in src]


_STR = r'"(?:[^"\\]|\\.)*"'


def _arrays(text, key):
    blocks = re.findall(r'"%s":\s*\[((?:\s*%s\s*,?)*)\s*\]' % (key, _STR), text)
    return [[json.loads(x) for x in re.findall(_STR, b)] for b in blocks]


def linear_a_words(path):
    """Multi-sign syllabic word tokens from lineara.xyz, e.g. ('A', 'SA', 'SA', 'RA', 'ME')."""
    pat = re.compile(r'^[A-Z][A-Z0-9₀-₉]*(-[A-Z][A-Z0-9₀-₉]*)+$')
    text = open(path, encoding='utf-8').read()
    return [tuple(w.split('-')) for arr in _arrays(text, 'transliteratedWords') for w in arr if pat.match(w)]


def linear_a_inscriptions(path):
    """Per-inscription runs of syllabic words, in order, for the known-plaintext control."""
    pat = re.compile(r'^[A-Z][A-Z0-9₀-₉]*(-[A-Z][A-Z0-9₀-₉]*)+$')
    text = open(path, encoding='utf-8').read()
    return [[tuple(w.split('-')) for w in arr if pat.match(w)] for arr in _arrays(text, 'transliteratedWords')]


def linear_b_words(corpus_path, lexicon_path):
    """Unique multi-sign Linear B words from the corpus plus the lexicon, e.g. ('te', 'o', 'jo')."""
    pat = re.compile(r'^[a-z][a-z0-9]*(-[a-z][a-z0-9]*)+$')
    text = open(corpus_path, encoding='utf-8').read()
    corpus = {w for arr in _arrays(text, 'transliteratedWords') for w in arr if pat.match(w)}
    lex = open(lexicon_path, encoding='utf-8').read()
    lexicon = {t.strip() for t in re.findall(r'"transcription":\s*"([^"]*)"', lex)}
    return {tuple(w.split('-')) for w in corpus | {w for w in lexicon if pat.match(w)}}
