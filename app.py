# Placeholder app.py (patch layer)
# Deze file is een patchlaag omdat het originele app.py in deze sessie niet aanwezig is.
# Voeg onderstaande functies/constantes toe aan jouw app.py, of vervang de bestaande definities ermee.

BREVET_CHOICES = ['K1ster','1ster','2ster','3ster','Asinst','1inst','2inst','3inst']

def canon_brevet(v):
    if v is None:
        return None
    s_orig = str(v)
    s = s_orig.strip().lower()
    if s in {'', '(geen)', 'geen', 'none', 'null'}:
        return None
    import re as _re
    s = _re.sub(r'[-–—‒−]', '', s)          # hyphens weg
    s = _re.sub(r'[＊∗⋆✱✳︎*]', '', s)       # asterisks weg
    s = s.replace('instructeur', 'inst')
    s = s.replace('assistent', 'as')
    s = s.replace('ass', 'as')
    s = s.replace(' ', '')
    if s in {'k1ster','k1'}:
        return 'K1ster'
    if s in {'1ster','1'}:
        return '1ster'
    if s in {'2ster','2'}:
        return '2ster'
    if s in {'3ster','3'}:
        return '3ster'
    if s in {'4ster','4'}:
        return '4ster'
    if s in {'asinst','assinst'}:
        return 'Asinst'
    if s == '1inst':
        return '1inst'
    if s == '2inst':
        return '2inst'
    if s == '3inst':
        return '3inst'
    return None

# Gebruik in je leden-upsert payload:
# 'duikbrevet': canon_brevet(None if brevet == '(geen)' else brevet),

# Gebruik voor default weergave in edit-form:
# cur_brevet = canon_brevet(row.get('duikbrevet')) or '(geen)'
