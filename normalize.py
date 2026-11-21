#!/usr/bin/env python3
"""normalize: text folding shared by the release gate and the allowlist validator.  Stdlib only (python 3.9).

Why it exists
  The gate looks for private values by (salted hash of) plain lower-case text.  An attacker, or a sloppy tool, can
  hide the SAME value from a plain match without changing how it reads to a human:

    * zero-width characters or a soft hyphen inside a word          Ze<U+200B>bediah
    * fullwidth letters                                             (fullwidth Latin letters)
    * accents                                                       Zebediah with accents
    * look-alike letters from another alphabet (Cyrillic, Greek)
    * escapes: \\u005a  \\x5a  &#90;  &#x5a;
    * adjacent string literals:  "Zebe" + "diah"
    * rot13, reversed, hex, or base64 of a differently cased value  (handled by the callers: see release_gate)

  fold() maps all of the "same text, different bytes" cases (first five groups and the escapes and the literal
  concatenation) to one canonical string, so ONE scan of the folded text covers them.  Folding only ever REMOVES or
  MAPS characters; it never invents text, so it can add false positives only when a private value really appears.

What it does NOT do (honest limits): it is not a general de-obfuscator.  Arbitrary encodings (custom ciphers, text
split by code that computes it, images of text) are out of scope; the README says so.

Public API
  fold(text)             -> canonical string (case is preserved; callers lower-case when they need to)
  rot13(text)            -> rot13 of text
  contains_private_word  is NOT here (it needs the values); see allowlist.py
"""
from __future__ import annotations

import codecs
import re
import unicodedata

# Escapes decoded before folding.  Each pattern captures the code point; invalid or huge numbers are left alone.
_U_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")                 # Z  (JSON / Python / JS)
_X_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")                 # \x5a    (Python / C / shell $'..')
_BIG_U_ESC = re.compile(r"\\U([0-9a-fA-F]{8})")             # \U0000005a (Python / C 8-digit form)
# F7: a UTF-16 surrogate PAIR written as two escapes (JSON for an astral character, e.g. a math-bold letter) is ONE
# character.  Decoding each half alone would produce two lone surrogates that cannot be encoded.
_SURR_PAIR_ESC = re.compile(r"\\u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})")
_PCT_U_PAIR = re.compile(r"%u([dD][89abAB][0-9a-fA-F]{2})%u([dD][c-fC-F][0-9a-fA-F]{2})")
_PCT_U = re.compile(r"%u([0-9a-fA-F]{4})")                  # %u007a (old JavaScript escape())
_BRACE_U_ESC = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}")     # \u{5a}     (JavaScript / Rust / Swift form)
# HTML numeric entities.  The closing semicolon is OPTIONAL because browsers accept "&#90" without it.
_DEC_ENT = re.compile(r"&#([0-9]{1,7});?")                  # &#90;   &#90
_HEX_ENT = re.compile(r"&#[xX]([0-9a-fA-F]{1,6});?")        # &#x5a;  &#x5a
# One or more %XX bytes in a row (percent-encoding).  Decoded as UTF-8 only when the whole run is valid UTF-8.
_PCT_RUN = re.compile(r"(?:%[0-9a-fA-F]{2})+")
# Separators that str.split("\n") does not treat as line ends and that NFKD/Cf-removal does not touch: vertical tab,
# form feed, NEL, line separator U+2028 and paragraph separator U+2029.  Dropping them re-joins a word cut by one.
_SEPARATORS = {0x0B: None, 0x0C: None, 0x85: None, 0x2028: None, 0x2029: None}
# Adjacent string literals: "ab" + "cd", 'ab' 'cd', "ab" . "cd".  The two quote characters and the glue between
# them are removed so the halves become one word.  Example: '"Zebe" + "diah"' -> '"Zebediah"'.
_CONCAT = re.compile(r"""(["'])\s*(?:\+|\.)?\s*\1""")

# Look-alike letters that NFKD does not turn into ASCII (Cyrillic and Greek capitals/smalls that look Latin).
# Maps to the Latin letter a reader would see.  Small on purpose: only true visual twins.
_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
    "ο": "o", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "υ": "u", "χ": "x",
}
_CONF_TABLE = {ord(k): v for k, v in _CONFUSABLE.items()}


def _chr_or_keep(m, base):
    """Replace one escape match with its character; keep the escape text if the number is not a valid code point."""
    try:
        cp = int(m.group(1), base)
        if 0xD800 <= cp <= 0xDFFF:
            return m.group(0)      # a LONE surrogate is not a character; keep the escape text (F7: it cannot be encoded)
        return chr(cp)
    except (ValueError, OverflowError):
        return m.group(0)


def _pair_to_char(m):
    """Combine the two halves of an escaped UTF-16 surrogate pair (hex in groups 1 and 2) into one character."""
    hi, lo = int(m.group(1), 16), int(m.group(2), 16)
    return chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))


def _pct_decode_run(m):
    """Decode one run of %XX bytes to text, or keep the run when it is not valid UTF-8 (so "%ff" stays)."""
    try:
        return bytes.fromhex(m.group(0).replace("%", "")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return m.group(0)


def percent_decode(text):
    """Decode percent-encoding TWICE, so both %7a and double-encoded %257a become 'z'.

    Every character may be encoded (not only reserved ones).  Invalid sequences are left as they are.
    Example: percent_decode('%7a%71') -> 'zq';  percent_decode('%257a') -> 'z'.
    """
    for _ in range(2):
        text = _PCT_RUN.sub(_pct_decode_run, text)
    return text


def decode_escapes(text):
    """Decode \\uXXXX (also surrogate pairs), %uXXXX, \\u{X..}, \\UXXXXXXXX, \\xXX, &#NN;/&#NN, &#xHH;/&#xHH and %XX (twice).

    Example: 'Z&#101;b' -> 'Zeb'.  Invalid or out-of-range numbers are left alone.
    """
    text = _SURR_PAIR_ESC.sub(_pair_to_char, text)           # before the single \\u rule, which would see two halves
    text = _PCT_U_PAIR.sub(_pair_to_char, text)
    text = _PCT_U.sub(lambda m: _chr_or_keep(m, 16), text)
    text = _BIG_U_ESC.sub(lambda m: _chr_or_keep(m, 16), text)
    text = _BRACE_U_ESC.sub(lambda m: _chr_or_keep(m, 16), text)
    text = _U_ESC.sub(lambda m: _chr_or_keep(m, 16), text)
    text = _X_ESC.sub(lambda m: _chr_or_keep(m, 16), text)
    text = _DEC_ENT.sub(lambda m: _chr_or_keep(m, 10), text)
    text = _HEX_ENT.sub(lambda m: _chr_or_keep(m, 16), text)
    return percent_decode(text)


def fold(text, join_literals=True):
    """Canonical form of TEXT for matching (see module docstring).  Order matters:

      1. decode escapes (so an escaped letter becomes a real one),
      2. join adjacent string literals,
      3. NFKD: fullwidth/compat letters become ASCII and accents split into base letter + combining mark,
      4. (also) drop VT, FF, NEL, U+2028, U+2029 so a word cut by one of them is whole again,
      4b. drop combining marks (category Mn) and format characters (category Cf: zero-width space/joiner, soft
         hyphen, BOM, word joiner, bidi marks) and carriage returns,
      5. map look-alike Cyrillic/Greek letters to Latin.
    Case is preserved.  Newlines are kept (callers split lines themselves).

    join_literals=False skips step 2.  The gate uses that for its PATTERN scan: source code legitimately builds fake
    secrets from pieces ("AKIA" + "EXAMPLE...") precisely so no token literal exists, and joining them would turn
    every such test fixture into a finding.  The VALUE scan keeps step 2 on (an owner name split that way is a leak).
    """
    text = decode_escapes(text)
    if join_literals:
        text = _CONCAT.sub("", text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if unicodedata.category(c) not in ("Mn", "Cf") and c != "\r")
    return text.translate(_CONF_TABLE).translate(_SEPARATORS)


def rot13(text):
    """rot13 of TEXT (letters only).  rot13 is its own inverse, so scanning rot13(text) finds rot13(value)."""
    return codecs.encode(text, "rot13")
