# SQLMAP — O'zbekcha versiya
TELEGRAM: https://t.me/cyber_studyorg

## Windowsda ishga tushirish

1. ZIP arxivni to'liq oching. Faqat `sqlmap.py` faylini alohida ko'chirmang.
2. `sqlmap.py` turgan `sqlmap-uz` papkasida terminal oching.
3. Quyidagi buyruqni kiriting:

```bat
python sqlmap.py -h
```

Barcha parametrlarni ko'rish:

```bat
python sqlmap.py -hh
```

Agar Windowsda `python` buyrug'i topilmasa, Python o'rnatilgan bo'lsa quyidagini sinab ko'ring:

```bat
py -3 sqlmap.py -hh
```

Grafik interfeys:

```bat
python sqlmap.py --gui
```

Grafik interfeys uchun Tkinter kerak. Matnli terminal interfeysi `--tui` bilan ochiladi;
buning uchun curses/ncurses qo'llovi kerak. Oddiy buyruq qatori bu modullarsiz ishlaydi.

## Linux yoki macOS

```sh
python3 sqlmap.py -hh
```

## Komandalar o'sha holicha

`-u`, `-r`, `-p`, `--dbs`, `--tables`, `--columns`, `--dump`, `--batch`,
`--level`, `--risk` va boshqa parametrlarning yozilishi hamda ma'nosi saqlangan.
Qo'shimcha til parametrini kiritish shart emas.

Faqat o'zingizga tegishli yoki tekshirishga ruxsat berilgan mahalliy sinov manzili bilan namuna:

```sh
python sqlmap.py -u "http://127.0.0.1:8000/item?id=1" --batch
```

Bu manzilda sinov saytingiz ishlayotgan bo'lishi kerak; arxiv sayt yoki laboratoriya serverini ishga tushirmaydi.

## Nimalar tarjima qilingan?

- Qisqa va batafsil yordam, parametr izohlari.
- Terminaldagi axborot, ogohlantirish, xato va holat xabarlari.
- Interaktiv savollar, sozlash yordamchisi, natija sarlavhalari.
- API mijozining yordam matnlari, grafik va terminal menyulari.
- `--list-tampers` orqali ko'rsatiladigan skript tavsiflari.
- `sqlmap.conf` faylidagi parametr izohlari.

Tarjima katalogida 3 409 ta matn/shablon bor; qo'shimcha menyu va tavsiflar ham moslangan.
O'zbekcha matnda oddiy apostrof ishlatilgan, shuning uchun Windows konsolida maxsus apostrof belgisi talab qilinmaydi.

## Nimalar asl holida qoladi?

- Buyruqlar, fayl nomlari, sozlash kalitlari va INI bo'limlari.
- SQL payloadlari, test nomlari, DBMS nomlari, texnik identifikatorlar.
- Serverdan kelgan ma'lumot, baza/jadval/ustun nomlari, so'rov va javoblar.
- API/JSON tuzilmasining kalitlari va INFO/WARNING kabi jurnal darajasi belgilari.
- Tashqi kutubxona yoki operatsion tizimning o'zi qaytargan xato matni.
- Dasturchilar uchun ichki izohlar, tashqi hujjatlar va litsenziya matni.

Shu sabab texnik nomlar yoki tashqi server xabarlari inglizcha ko'rinishi mumkin.
`--test-filter` va `--test-skip` uchun avvalgi test nomlarini ishlatishda davom eting.

## Savollarga javob berish

Javob harflari o'zgarmagan:

- `Y` — ha; `N` — yo'q.
- `[Y/n]` da Enter bosilsa, ha tanlanadi.
- `[y/N]` da Enter bosilsa, yo'q tanlanadi.
- `q` — chiqish; raqamli menyuda ko'rsatilgan raqam ishlatiladi.
- `--batch` avvalgidek standart javoblarni ishlatadi.

`--answers="quit=N,follow=N"` kabi mavjud inglizcha kalitli buyruqlar mosligi saqlangan.
O'zbekcha savol matnidan parcha bilan moslashtirish ham qo'llanadi.

## Yangilash haqida

`--update` asl sqlmap yangilash mexanizmini chaqiradi. U rasmiy inglizcha fayllarni yuklab,
ushbu mahalliy tarjimani almashtirishi mumkin. Yangilashdan oldin o'zbekcha arxivni saqlab qo'ying.

## Tekshiruvlar

Sinov tafsilotlari: `UZBEK/TEKSHIRUV.md`.

- 2 742 ta unittest: xatosiz, 15 tasi o'tkazib yuborilgan.
- Sqlmapning ichki `--smoke-test` sinovi muvaffaqiyatli.
- 284 ta CLI parametr ta'rifi asl nusxa bilan bir xil.
- `data/` ichidagi 107 ta fayl va `thirdparty/` ichidagi 72 ta fayl baytma-bayt bir xil.
- Sozlash faylining qiymatlari va bo'lim/kalit nomlari saqlangan.

Sinovlar Linux/Python 3.12 muhitida o'tkazilgan. Windows va grafik interfeysning ekrandagi
joylashuvi bu muhitda alohida tekshirilmagan. Uchinchi tomon saytlariga tekshiruv yuborilmadi.

## Mualliflik

Asl loyiha: sqlmap developers — https://sqlmap.org
Asl kod va litsenziya saqlangan. `LICENSE` faylini ko'ring.
Asl inglizcha tanishtiruv: `README_ORIGINAL.md`.
