# Ślad Metadanych

Aplikacja PHP do odczytu i porównywania metadanych plików:

Aktualna wersja: `0.001` (plik `VERSION`). Hook Git `.githooks/pre-commit` zwiększa wersję o `0.001` przy każdym commicie. Aby go włączyć w lokalnym klonie, wykonaj:

```sh
git config core.hooksPath .githooks
```

- PDF: podstawowe pola słownika informacji, takie jak autor, tytuł, temat, program i daty.
- DOCX, XLSX, PPTX: właściwości dokumentu, w tym autor, firma i osoba ostatnio modyfikująca.
- JPG, TIFF: dostępne dane EXIF, między innymi autor, opis, daty, aparat i prawa autorskie.
- PDF: wykrywanie podpisów CMS, weryfikacja integralności zakresu `ByteRange` i odczyt certyfikatu podpisującego.
- Office Open XML: wykrywanie podpisu XMLDSIG; jego weryfikacja kryptograficzna nie jest jeszcze obsługiwana.

## Uruchomienie

Wymagany PHP 8.0 lub nowszy. Rozszerzenie `zip` jest potrzebne dla plików Office, a `exif` dla obrazów.

```sh
php -S 127.0.0.1:8000
```

Otwórz `http://127.0.0.1:8000`.

Pliki są przetwarzane w katalogu tymczasowym PHP i nie są zapisywane w katalogu aplikacji. Limit wynosi 20 MB na plik i 10 plików na analizę. Porównanie ignoruje wielkość liter i nadmiarowe białe znaki. Szyfrowane PDF-y oraz wartości zapisane wyłącznie w niestandardowych rozszerzeniach mogą nie zostać odczytane. W konfiguracji PHP `upload_max_filesize` i `post_max_size` powinny wynosić co najmniej 20 MB.

Wynik integralności podpisu PDF jest niezależny od zaufania do certyfikatu. Zaufanie jest sprawdzane względem lokalnego magazynu OpenSSL; aplikacja nie odpytuje CRL ani OCSP, więc nie potwierdza, czy certyfikat został unieważniony. Typowe pliki JPG/TIFF nie przechowują podpisu cyfrowego w obsługiwanym przez tę aplikację formacie.