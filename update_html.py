# -*- coding: utf-8 -*-

"""
update_html.py

Рекурсивно оновлює усі *.html‑файли у каталозі SITE_ROOT:

1. Вставляє <script src="/preview.js"></script> перед </body>,
   уникаючи дублювання.
2. Додає target="_blank" rel="noopener noreferrer" до **кожного** <a>.
3. Оновлює <meta http-equiv="Content‑Security‑Policy">
   (або X‑Content‑Security‑Policy), додаючи 'self' до script‑src.
   Зберігає оригінальний стиль апострофа (`'` або `&#39;`).
4. Підтримує різні кодування файлів, записуючи їх у UTF‑8.
5. **Безпечний запис:** якщо файл не доступний для запису,
   скрипт просто пропускає його і продовжує роботу.

Використання:
    python3 update_html.py
"""

import sys
import re
import html as html_mod               # для розкодування/закодування HTML‑ентітей
from pathlib import Path

# ---------- 3‑rd party -------------------------------------------------
try:
    from bs4 import BeautifulSoup, Comment
except ImportError:                     # інформуємо користувача
    sys.exit("Помилка: потрібно встановити BeautifulSoup4 → pip install beautifulsoup4")

# -------------------------------------------------
# ⚙️  Налаштування (змініть під ваш проєкт)
# -------------------------------------------------
SITE_ROOT = Path("/home/oleksandr/Backups/uk/commentaries")   # ← ← змініть на реальний шлях

# -------------------------------------------------
# 📦  Підтримка різних кодувань
# -------------------------------------------------
try:
    # Python 3.10+ постачається з charset_normalizer
    from charset_normalizer import from_bytes as detect_encoding
except ImportError:
    # Якщо charset_normalizer відсутній, спробуємо chardet
    try:
        import chardet

        def detect_encoding(b):
            """Повертає dict, схожий на те, що повертає charset_normalizer."""
            return chardet.detect(b)
    except ImportError:
        detect_encoding = None   # без бібліотеки – будемо читати з errors='replace'


def read_file_smart(path: Path) -> str:
    """Читає файл, намагаючись визначити його кодування."""
    raw = path.read_bytes()

    # 1️⃣ Спроба UTF‑8
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        pass

    # 2️⃣ Спроба визначити кодування (charset‑normalizer / chardet)
    if detect_encoding:
        result = detect_encoding(raw)
        enc = result.get('encoding')
        conf = result.get('confidence', 0)
        if enc and conf > 0.5:
            try:
                return raw.decode(enc)
            except Exception:
                pass

    # 3️⃣ Фолбек – замінюємо невірні байти
    return raw.decode('utf-8', errors='replace')


def write_file_utf8(path: Path, text: str):
    """
    Записує рядок у файл у кодуванні UTF‑8.
    Якщо запис неможливий (наприклад, немає прав), виводить попередження
    і продовжує роботу.
    """
    try:
        path.write_text(text, encoding='utf-8')
    except PermissionError as e:
        print(f"[⚠️] Не вдалося записати {path.relative_to(SITE_ROOT)}: {e}")
    except OSError as e:
        # Інші можливі помилки (наприклад, файл заблоковано)
        print(f"[⚠️] Помилка запису {path.relative_to(SITE_ROOT)}: {e}")


# -------------------------------------------------
# 🛠️  Операції над HTML (BeautifulSoup)
# -------------------------------------------------
SCRIPT_TAG = '<script src="/preview.js"></script>'


def ensure_script(soup: BeautifulSoup) -> bool:
    """Додає <script src="/preview.js"></script> перед </body>, якщо ще немає."""
    if soup.find('script', src=re.compile(r'^/preview\.js$', re.IGNORECASE)):
        return False                     # вже є

    new_tag = soup.new_tag('script', src="/preview.js")
    if soup.body:
        soup.body.append(new_tag)
    else:
        soup.append(new_tag)
    return True


def add_target_blank(soup: BeautifulSoup) -> bool:
    """Додає target="_blank" rel="noopener noreferrer" до всіх <a> без target."""
    changed = False
    for a in soup.find_all('a'):
        if a.has_attr('target'):
            continue
        a['target'] = '_blank'
        a['rel'] = 'noopener noreferrer'
        changed = True
    return changed


def adjust_body(soup: BeautifulSoup) -> bool:
    """Вставка скрипту + атрибути посилань."""
    return ensure_script(soup) or add_target_blank(soup)


def adjust_csp_meta(soup: BeautifulSoup) -> bool:
    """
    Оновлює <meta http-equiv="Content‑Security‑Policy">
    (або X‑Content‑Security‑Policy), додаючи 'self' до script-src.
    Зберігає стиль апострофа (`'` або `&#39;`).
    """
    meta = soup.find('meta',
                     attrs={'http-equiv': re.compile(
                         r'^(Content-Security-Policy|X-Content-Security-Policy)$',
                         re.IGNORECASE)})

    if not meta or not meta.has_attr('content'):
        return False

    raw_content = meta['content']               # може містити &#39;
    decoded = html_mod.unescape(raw_content)    # розкодуємо

    directives = [d.strip() for d in decoded.split(';') if d.strip()]

    new_directives = []
    script_src_found = False
    for d in directives:
        if d.lower().startswith('script-src'):
            parts = d.split()
            sources = parts[1:]
            if not any(src.strip("'\"") == 'self' for src in sources):
                sources.append("'self'")
            new_directives.append('script-src ' + ' '.join(sources))
            script_src_found = True
        else:
            new_directives.append(d)

    if not script_src_found:
        new_directives.append("script-src 'self'")

    new_content = '; '.join(new_directives)

    # Якщо в оригіналі був &#39;, повертаємо його назад
    if '&#39;' in raw_content:
        new_content = new_content.replace("'", "&#39;")

    if new_content == raw_content:
        return False

    meta['content'] = new_content
    return True


def process_file(path: Path) -> None:
    """Читає, модифікує та записує файл (у UTF‑8)."""
    original_html = read_file_smart(path)

    soup = BeautifulSoup(original_html, 'html.parser')

    # Видаляємо коментарі – це не обов’язково, просто чистіше
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    body_changed = adjust_body(soup)
    csp_changed  = adjust_csp_meta(soup)

    if body_changed or csp_changed:
        # prettify форматує HTML, а formatter="html" зберігає суттєві символи
        write_file_utf8(path, soup.prettify(formatter="html"))
        print(f"✓ Оновлено {path.relative_to(SITE_ROOT)}")
    else:
        print(f"= {path.relative_to(SITE_ROOT)} – без змін")


# -------------------------------------------------
# 🚀  Рекурсивна обробка всіх *.html у SITE_ROOT
# -------------------------------------------------
def walk_and_update():
    """
    Рекурсивно перебирає всі *.html‑файли у каталозі SITE_ROOT
    (включаючи підкаталоги) і викликає process_file().
    """
    for html_path in SITE_ROOT.rglob('*.html'):   # рекурсивно!
        process_file(html_path)


# -------------------------------------------------
# 🏁  Головна функція
# -------------------------------------------------
def main():
    if not SITE_ROOT.is_dir():
        sys.exit(f"[!] Каталог {SITE_ROOT} не існує.")

    walk_and_update()
    print("\n✅ Готово! Перевірте ваш сайт.\n"
          "   • При увімкненому JavaScript працює прев’ю.\n"
          "   • При вимкненому JavaScript посилання відкриваються у новій вкладці.\n"
          "   • CSP‑meta‑тег тепер містить \"script-src 'self'\" (у тому ж форматі, що й раніше).\n")


if __name__ == '__main__':
    main()
