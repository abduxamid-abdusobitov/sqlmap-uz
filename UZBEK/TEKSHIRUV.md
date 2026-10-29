# Tekshiruv natijalari

Muhit: Linux, Python 3.12. Sana: 2026-10-29.
Upstream: `c42ebd7acf47c88b6407995dd9842a2eb5d6534d` (`1.10.10.29#dev`).

## Natija

- `python -m unittest discover -s tests -q`: 2 755 test, OK, 15 skipped.
- `python sqlmap.py --smoke-test`: MUVAFFAQIYATLI.
- `python sqlmap.py --doc-test`: MUVAFFAQIYATLI.
- `python sqlmap.py --payload-lint`: 51 037 payload, 31/31 DBMS, 0 xato.
- Pyflakes: toza (CI kabi `redefines` xabarlari chiqarib tashlangan).
- Barcha Python manba fayllari kompilyatsiya tekshiruvidan o'tdi.
- AST orqali tekshirilgan 275 ta CLI parametr ta'rifi (help matnidan tashqari) yangi original bilan teng.
- `data/`: 107 fayl; `thirdparty/`: 72 fayl yangi original bilan baytma-bayt teng.
- `sqlmap.conf`: bo'limlar, kalitlar va qiymatlar yangi original bilan teng.
- 3 409 ta tarjima katalogi yozuvida format belgilari tekshirildi.

## Regressiya testlari

Oldingi o'zbekcha yordam, Y/N javoblari, inglizcha va o'zbekcha `--answers` kalitlari
hamda dinamik qiymatlarning saqlanishi testlari qolgan.

Yangilashga oid 8 ta yangi offline test: o'chirilgan update rejimi, ZIP fayllarini saqlash,
mahalliy tahrirlarni saqlash, SQLMAP-UZ/main va `--ff-only` tanlovi, worktree `.git` fayli,
Git status xatosi, ajralgan tarix va Git o'rnatilmagan holat.
Upstreamdan Burp XML va proxy autentifikatsiyasi regressiya testlari ham olindi.

## Chegaralar

Windows/Python 3.14, PyPy 2.7 va grafik interfeys bu lokal muhitda amaliy tekshirilmadi.
15 ta test ixtiyoriy bog'liqlik yoki maxsus muhit talab qilgani uchun o'tkazib yuborildi.
Tashqi saytlarga skanerlash bajarilmadi. Yangilash testlari Git natijalarini taqlid qiladi;
haqiqiy tarmoq orqali foydalanuvchi nusxasini yangilamaydi.
