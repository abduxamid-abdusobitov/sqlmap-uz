# 2026-10-29 yangilanishi

SQLMAP-UZ asosi `1.10.10.20#dev` dan `1.10.10.29#dev` ga yangilandi.

- Oldingi upstream: `6e06114947397e1f5bbe428230e25cf1cf9f1a55`.
- Tekshirilgan yangi upstream: `c42ebd7acf47c88b6407995dd9842a2eb5d6534d`.
- Manba: https://github.com/sqlmapproject/sqlmap/compare/6e06114947397e1f5bbe428230e25cf1cf9f1a55...c42ebd7acf47c88b6407995dd9842a2eb5d6534d

## Originaldan olingan tuzatishlar

9 ta upstream commitdagi o'zgarishlar o'zbekcha matnlar saqlangan holda kiritildi:

- Python 3.14 da Ctrl+C dan keyin kesh qulflari sabab qotib qolishni tuzatish.
- Parallel ishlashda keshdan o'chgan element uchun `KeyError` ni qayta ishlash.
- Proxy URL ichidagi login/parol va URL-kodlangan belgilarni to'g'ri uzatish.
- Burp XML tarixidagi HTTPS protokoli va nostandart portlarni saqlash.
- HTTP javob kodi `None` bo'lganda ogohlantirish chiqarishdagi `TypeError` ni tuzatish.
- Xato hisobotiga Python build/JIT ma'lumotlarini qo'shish.
- Tegishli upstream regressiya testlari.

## SQLMAP-UZ uchun tuzatishlar

- `--update` endi SQLMAP-UZ repozitoriysining `main` branchidan yangilaydi.
- Yangilashdan oldin mahalliy tahrirlar tekshiriladi. `git checkout .` olib tashlandi.
- Faqat fast-forward yangilashga ruxsat beriladi; ajralgan tarix majburan almashtirilmaydi.
- ZIP nusxasini yangilash uchun fayllarni o'chiradigan yo'l olib tashlandi.
- PyPy/Python 2.7 da oddiy satrni o'zbekcha savolga qo'shishdagi Unicode xatosi tuzatildi.
- GitHub Actions `master` o'rniga ushbu reponing `main` branchida ishlaydi.
- Ishlatilmayotgan test importi olib tashlandi; pyflakes tekshiruvi toza.
- O'zgargan xabarlar tarjima katalogida ham yangilandi.

Tekshiruv natijalari: [TEKSHIRUV.md](TEKSHIRUV.md).
