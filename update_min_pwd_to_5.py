
import re
from pathlib import Path

APP = Path("app.py")
if not APP.exists():
    raise SystemExit("Kon 'app.py' niet vinden in de huidige map. Zet dit script naast je app.py en voer het opnieuw uit.")

src = APP.read_text(encoding="utf-8", errors="ignore")
bak = Path("app.py.bak")
bak.write_text(src, encoding="utf-8")

def repl_contextual_len_checks(text: str) -> str:
    out_lines = []
    for line in text.splitlines(keepends=False):
        lower = line.lower()
        # Alleen regels die duidelijk met wachtwoord/password te maken hebben
        if ("pass" in lower or "wacht" in lower):
            # len(x) < 8  -> len(x) < 5
            line = re.sub(r"(len\s*\(\s*[^)]*\)\s*<\s*)8\b", r"\g<1>5", line)
            # len(x) <= 7 -> len(x) <= 4  (komt zelden voor, maar voor de zekerheid)
            line = re.sub(r"(len\s*\(\s*[^)]*\)\s*<=\s*)7\b", r"\g<1>4", line)
            # len(x) >= 8 -> len(x) >= 5  (soms wordt 'goed' gecheckt i.p.v. 'fout')
            line = re.sub(r"(len\s*\(\s*[^)]*\)\s*>=\s*)8\b", r"\g<1>5", line)
            # Min/Help-tekst: "8 teken(s)" -> "5 teken(s)"
            line = re.sub(r"8(\s*)(teken|tekens)", r"5\1\2", line, flags=re.IGNORECASE)
            # Veel voorkomende constanten
            line = re.sub(r"(?i)(MIN[\s_]*PWD[\s_]*LEN\s*=\s*)8\b", r"\g<1>5", line)
            line = re.sub(r"(?i)(MIN[\s_]*PASS[\s_]*LEN\s*=\s*)8\b", r"\g<1>5", line)
            line = re.sub(r"(?i)(MIN[\s_]*WACHTWOORD[\s_]*LENGTE\s*=\s*)8\b", r"\g<1>5", line)
        out_lines.append(line)
    return "\n".join(out_lines)

updated = repl_contextual_len_checks(src)

# Als niets is aangepast, meld dat netjes
if updated == src:
    print("Geen regels gevonden die met wachtwoordlengte (8) te maken hebben. Niets aangepast.")
else:
    APP.write_text(updated, encoding="utf-8")
    print("Klaar. 'app.py' is aangepast (min. wachtwoordlengte 5). Back-up staat in 'app.py.bak'.")
