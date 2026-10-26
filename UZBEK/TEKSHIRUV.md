# Tekshiruv natijalari

Muhit: Linux, Python 3.12.14. Sana: 2026-10-26.

## Natija

- `python -m unittest discover -s tests -q`: 2 742 ta test, OK, 15 skipped.
- `python sqlmap.py --smoke-test`: MUVAFFAQIYATLI.
- `python sqlmap.py -h`, `-hh`, `--version`, `--list-tampers`, `sqlmapapi.py -h`: bajarildi.
- Barcha Python manba fayllari kompilyatsiya tekshiruvidan o'tdi.
- 284 ta argument/parametrning flag, dest, action, type, metavar va standart sozlamalari asl nusxaga mos.
- `data/`: 107 fayl o'zgarishsiz. `thirdparty/`: 72 fayl o'zgarishsiz.
- `LICENSE`: o'zgarishsiz.
- `sqlmap.conf`: bo'limlar, kalitlar va qiymatlar tengligi INI tahlilchisi orqali tekshirildi.

## Tarjimaga oid testlar

O'zbekcha yordam, Y/N standartlari, inglizcha `--answers` kalitlari, o'zbekcha kalitlar,
savollarga qo'shilgan dinamik qiymatlar va satrlarni birlashtirish tekshirildi.
Asl testlardagi inglizcha chiqish matnini tekshiruvchi kutishlar o'zbekcha ko'rinishga
moslandi. Funksional tekshiruvlar o'chirilmadi.

## Chegaralar

Windowsda amaliy ishga tushirish va grafik interfeysning vizual tekshiruvi bajarilmadi.
O'tkazib yuborilgan testlar ixtiyoriy bog'liqlik yoki maxsus muhit talab qiladi.
Tashqi saytlarga skanerlash bajarilmadi.
