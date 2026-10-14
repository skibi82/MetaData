# Ślad Metadanych

Aplikacja PHP do odczytu i porównywania metadanych plików:

Aktualna wersja znajduje się w pliku `VERSION`. Hook Git `.githooks/pre-commit` zwiększa ją o `0.001` przy każdym commicie. Aby go włączyć w lokalnym klonie, wykonaj:

```sh
git config core.hooksPath .githooks
```

- PDF: podstawowe pola słownika informacji, takie jak autor, tytuł, temat, program i daty.
- DOCX, XLSX, PPTX: właściwości dokumentu, w tym autor, firma, osoba ostatnio modyfikująca i łączny czas edycji w minutach/godzinach.
- JPG, TIFF: dostępne dane EXIF, między innymi autor, opis, daty, aparat, prawa autorskie i lokalizacja GPS z linkiem do Google Maps.
- PDF: wykrywanie podpisów CMS, weryfikacja integralności zakresu `ByteRange`, odczyt certyfikatu podpisującego i online sprawdzanie jego statusu na CRL wskazanym w certyfikacie.
- Office Open XML: wykrywanie podpisu XMLDSIG; jego weryfikacja kryptograficzna nie jest jeszcze obsługiwana.

## Uruchomienie

Wymagany PHP 8.0 lub nowszy. Rozszerzenie `zip` jest potrzebne dla plików Office, `exif` dla obrazów, a `curl`, `dom` i `openssl` do pobrania TSL/CRL oraz weryfikacji podpisów i pełnego łańcucha PDF.

```sh
php -S 127.0.0.1:8000
```

Otwórz `http://127.0.0.1:8000`.

Pliki są przetwarzane w katalogu tymczasowym PHP i nie są zapisywane w katalogu aplikacji. Limit wynosi 20 MB na plik i 10 plików na analizę. Porównanie ignoruje wielkość liter i nadmiarowe białe znaki. Szyfrowane PDF-y oraz wartości zapisane wyłącznie w niestandardowych rozszerzeniach mogą nie zostać odczytane. W konfiguracji PHP `upload_max_filesize` i `post_max_size` powinny wynosić co najmniej 20 MB.

Daty utworzenia i modyfikacji z PDF, Office i EXIF są wyświetlane jako `YYYY-MM-DD HH:mm` w języku przeglądarki. Gdy plik zawiera offset lub strefę czasową, godzina jest przeliczana do lokalnej strefy urządzenia przeglądającego. Daty bez informacji o strefie zachowują zapisany czas lokalny, ponieważ nie da się wiarygodnie ustalić ich offsetu.

## Sprawdzanie CRL

Aplikacja buduje łańcuch od certyfikatu podpisującego przez certyfikaty pośrednie do aktywnego korzenia z polskiej TSL. Weryfikuje podpis i skróty XMLDSIG TSL, jej okres ważności oraz certyfikat operatora TSL przypięty odciskiem SHA-256. Certyfikaty pośrednie są pobierane z CMS lub AIA, a pełną ścieżkę sprawdza OpenSSL względem korzenia z TSL. Urząd bezpośrednio wystawiający certyfikat podpisującego musi mieć w aktualnej TSL usługę `CA/QC` ze statusem `granted` oraz kwalifikacjami `ForeSignatures` i `QCForESig`.

Status CRL jest weryfikowany dla każdego certyfikatu poza korzeniem, na podstawie jego `CRL Distribution Points`; obejmuje to również listy ARL NCCert dla certyfikatów Sub-CA. Nie ma jednej wspólnej CRL dla wszystkich wystawców. Obsługiwane są pełne, bezpośrednie listy CRL bez ograniczeń punktu dystrybucji. Niedostępna, nieaktualna lub nieobsługiwana lista daje status nieznany, a nie pozytywny. Jeśli nie można zweryfikować podpisanej TSL, kwalifikacji CA/QC lub aktywnego korzenia, aplikacja nie uznaje ścieżki za zaufaną. Zmiana certyfikatu operatora TSL wymaga aktualizacji przypiętego odcisku; do tego czasu walidacja TSL kończy się statusem nieznanym.

Polska Zaufana Lista (TSL) publikowana przez Narodowe Centrum Certyfikacji zawiera kwalifikowanych dostawców i punkty dystrybucji usług: [PL_TSL.xml](https://www.nccert.pl/tsl/PL_TSL.xml), [opis TSL](https://www.nccert.pl/tsl.htm). Przykłady punktów CRL usług certyfikacji widocznych w TSL: KIR `http://elektronicznypodpis.pl/crl/crl_ozk62.crl`, PWPW/Sigillum `http://crl.sigillum.pl/repozytorium/qca2_2026.crl`, Cencert `http://crl.cencert.pl/crl/qca_2023.crl`, EuroCert `http://crl.eurocert.pl/qca06.crl` i Certum `http://qcag3r35.crl.certum.pl/qcag3r35.crl` (stan sprawdzenia: 13 października 2026 r.). Konkretne certyfikaty mogą wskazywać inne lub nowsze adresy; aplikacja pobiera je z certyfikatu.

CRL publikowane przez NCCert na stronie [Lista CRL](https://www.nccert.pl/crl.htm) (`nccert2016.crl`, `nccert-n.crl` i `nccert.crl`) dotyczą certyfikatów dostawców wydanych przez krajowe urzędy NCCert. Nie są zamiennikiem CRL urzędu, który wystawił certyfikat osoby podpisującej.

Integralność kryptograficzna podpisu, weryfikacja łańcucha do polskiego korzenia, lokalne zaufanie OpenSSL i status CRL są odrębnymi wynikami. Wpis CA/QC w TSL nie stanowi sam w sobie pełnej oceny wszystkich cech podpisu kwalifikowanego, w tym użycia QSCD i wiarygodnego znacznika czasu. OCSP nie jest obsługiwane. Typowe pliki JPG/TIFF nie przechowują podpisu cyfrowego w obsługiwanym przez tę aplikację formacie.