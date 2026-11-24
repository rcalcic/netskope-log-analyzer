#!/usr/bin/env python3
"""Gera o site do app (PWA instalável) em ./site para o GitHub Pages."""
import base64, pathlib, shutil
root = pathlib.Path(__file__).resolve().parent.parent
v = (root / 'VERSION').read_text().strip()
out = root / 'site'
shutil.rmtree(out, ignore_errors=True); out.mkdir()
fav = base64.b64encode((root / 'assets/icon-64.png').read_bytes()).decode()
html = (root / 'src/index.html').read_text(encoding='utf-8')
html = html.replace('<title>Netskope Log Analyzer</title>',
    f'<title>Netskope Log Analyzer</title>\n<link rel="icon" type="image/png" href="data:image/png;base64,{fav}">', 1).replace('__VERSION__', v)
(out / 'index.html').write_text(html, encoding='utf-8')
(out / 'sw.js').write_text((root / 'web/sw.js').read_text(encoding='utf-8').replace('__VERSION__', v), encoding='utf-8')
shutil.copy(root / 'web/manifest.webmanifest', out)
for n in ('icon-192.png', 'icon-512.png', 'icon-maskable-512.png'):
    shutil.copy(root / 'assets' / n, out)
(out / '.nojekyll').touch()
print(f'site v{v}:', ', '.join(sorted(p.name for p in out.iterdir())))
