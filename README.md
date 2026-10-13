# Ślad Metadanych

Aplikacja PHP do odczytu i porównywania metadanych plików:

Aktualna wersja znajduje się w pliku `VERSION`. Hook Git `.githooks/pre-commit` zwiększa ją o `0.001` przy każdym commicie. Aby go włączyć w lokalnym klonie, wykonaj:

```sh
git config core.hooksPath .githooks
```

- PDF: podstawowe pola słownika informacji, takie jak autor, tytuł, temat, program i daty.
- DOCX, XLSX, PPTX: właściwości dokumentu, w tym autor, firma i osoba ostatnio modyfikująca.
- JPG, TIFF: dostępne dane EXIF, między innymi autor, opis, daty, aparat i prawa autorskie.
- PDF: wykrywanie podpisów CMS, weryfikacja integralności zakresu `ByteRange`, odczyt certyfikatu podpisującego i online sprawdzanie jego statusu na CRL wskazanym w certyfikacie.
- Office Open XML: wykrywanie podpisu XMLDSIG; jego weryfikacja kryptograficzna nie jest jeszcze obsługiwana.

## Uruchomienie

Wymagany PHP 8.0 lub nowszy. Rozszerzenie `zip` jest potrzebne dla plików Office, `exif` dla obrazów, a `curl` do online sprawdzania CRL. Rozszerzenie `openssl` jest potrzebne do weryfikacji podpisów PDF.

```sh
php -S 127.0.0.1:8000
```

Otwórz `http://127.0.0.1:8000`.

Pliki są przetwarzane w katalogu tymczasowym PHP i nie są zapisywane w katalogu aplikacji. Limit wynosi 20 MB na plik i 10 plików na analizę. Porównanie ignoruje wielkość liter i nadmiarowe białe znaki. Szyfrowane PDF-y oraz wartości zapisane wyłącznie w niestandardowych rozszerzeniach mogą nie zostać odczytane. W konfiguracji PHP `upload_max_filesize` i `post_max_size` powinny wynosić co najmniej 20 MB.

## Sprawdzanie CRL

Aplikacja odczytuje adresy z rozszerzenia `CRL Distribution Points` certyfikatu podpisującego. Nie utrzymuje statycznej listy adresów operatorów, ponieważ dostawcy mogą publikować osobne CRL dla kolejnych urzędów i generacji certyfikatów. Przed wynikiem „nie figuruje na CRL” sprawdzane są: certyfikat wystawcy pobrany z AIA lub osadzony w CMS, jego podpis pod certyfikatem podpisującego, podpis i wystawca listy CRL oraz jej okres ważności. Obsługiwane są pełne, bezpośrednie listy CRL bez ograniczeń punktu dystrybucji; niedostępna, nieaktualna lub nieobsługiwana lista daje status nieznany, a nie pozytywny.

Polska Zaufana Lista (TSL) publikowana przez Narodowe Centrum Certyfikacji zawiera kwalifikowanych dostawców i punkty dystrybucji usług: [PL_TSL.xml](https://www.nccert.pl/tsl/PL_TSL.xml), [opis TSL](https://www.nccert.pl/tsl.htm). Przykłady punktów CRL usług certyfikacji widocznych w TSL: KIR `http://elektronicznypodpis.pl/crl/crl_ozk62.crl`, PWPW/Sigillum `http://crl.sigillum.pl/repozytorium/qca2_2026.crl`, Cencert `http://crl.cencert.pl/crl/qca_2023.crl`, EuroCert `http://crl.eurocert.pl/qca06.crl` i Certum `http://qcag3r35.crl.certum.pl/qcag3r35.crl` (stan sprawdzenia: 13 października 2026 r.). Konkretne certyfikaty mogą wskazywać inne lub nowsze adresy; aplikacja pobiera je z certyfikatu.

CRL publikowane przez NCCert na stronie [Lista CRL](https://www.nccert.pl/crl.htm) (`nccert2016.crl`, `nccert-n.crl` i `nccert.crl`) dotyczą certyfikatów dostawców wydanych przez krajowe urzędy NCCert. Nie są zamiennikiem CRL urzędu, który wystawił certyfikat osoby podpisującej.

Wynik integralności podpisu PDF, status CRL i zaufanie do łańcucha są odrębnymi informacjami. Zaufanie jest sprawdzane względem lokalnego magazynu OpenSSL; status CRL nie potwierdza sam w sobie kwalifikowanego statusu usługi. OCSP nie jest obsługiwane. Typowe pliki JPG/TIFF nie przechowują podpisu cyfrowego w obsługiwanym przez tę aplikację formacie.