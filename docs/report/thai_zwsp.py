"""Copy the report sources to build/src and insert U+200B between Thai words.

tectonic's bundled ICU has no Thai dictionary, so XeTeX cannot find line breaks
inside Thai text. Thai runs never contain LaTeX commands, so segmenting each
maximal run of Thai characters is safe. The sources in git stay clean.
"""
import pathlib
import re
import shutil

from pythainlp.tokenize import word_tokenize

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "build" / "src"
THAI = re.compile(r"[\u0E00-\u0E7F]+")
NO_BREAK_BEFORE = "ๆฯ"      # a line must not start with these


def split_run(m: re.Match) -> str:
    out = ""
    for tok in word_tokenize(m.group(0), engine="newmm"):
        if out and tok[0] not in NO_BREAK_BEFORE:
            out += "\u200b"
        out += tok
    return out


if SRC.exists():
    shutil.rmtree(SRC)
SRC.mkdir(parents=True)
for p in HERE.rglob("*"):
    if "build" in p.relative_to(HERE).parts or p.is_dir():
        continue
    if p.suffix in (".py", ".sh", ".md") or p.name.startswith("."):
        continue
    dst = SRC / p.relative_to(HERE)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if p.suffix == ".tex":
        dst.write_text(THAI.sub(split_run, p.read_text(encoding="utf-8")), encoding="utf-8")
    else:
        shutil.copy2(p, dst)
print(f"prepared {SRC}")
