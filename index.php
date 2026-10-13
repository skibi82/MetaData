<?php
declare(strict_types=1);

session_start();

const MAX_FILE_SIZE = 20 * 1024 * 1024;
const MAX_FILES = 10;
const POLISH_TSL_URL = 'https://www.nccert.pl/tsl/PL_TSL.xml';
const POLISH_TSL_OPERATOR_FINGERPRINT = '446A041A550BC51B92525EF7E540090B2DF67F0852E5C7ADDB96661CCE330596';

$labels = [
    'author' => 'Autor', 'company' => 'Firma', 'title' => 'Tytuł',
    'subject' => 'Temat', 'keywords' => 'Słowa kluczowe',
    'description' => 'Opis', 'created' => 'Data utworzenia',
    'modified' => 'Data modyfikacji', 'last_modified_by' => 'Ostatnio zmodyfikował',
    'editing_time' => 'Łączny czas edycji',
    'software' => 'Program', 'producer' => 'Producent', 'manager' => 'Osoba kontaktowa',
    'copyright' => 'Prawa autorskie', 'camera' => 'Aparat',
];
$version = trim((string) (@file_get_contents(__DIR__ . '/VERSION') ?: '0.001'));

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function addMetadata(array &$metadata, string $key, mixed $value): void
{
    if (is_array($value)) {
        $value = implode(', ', array_filter(array_map('strval', $value)));
    }
    if (!is_scalar($value)) {
        return;
    }
    $value = trim((string) $value);
    if ($value !== '') {
        $metadata[$key] = $value;
    }
}

function xmlProperty(SimpleXMLElement $xml, string $name): string
{
    $nodes = $xml->xpath('//*[local-name()="' . $name . '"]');
    return $nodes ? trim((string) $nodes[0]) : '';
}

function formatEditingTime(string $value): string
{
    if (!ctype_digit($value)) {
        return $value;
    }
    $minutes = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
    if ($minutes === false) {
        return $value . ' min';
    }
    $hours = intdiv($minutes, 60);
    $remainingMinutes = $minutes % 60;
    if ($hours === 0) {
        return $minutes . ' min';
    }
    $duration = $hours . ' godz.';
    if ($remainingMinutes > 0) {
        $duration .= ' ' . $remainingMinutes . ' min';
    }
    return $duration . ' (' . $minutes . ' min)';
}

function extractOfficeMetadata(string $path): array
{
    if (!class_exists(ZipArchive::class)) {
        return ['error' => 'Odczyt plików Office wymaga rozszerzenia PHP ZipArchive.'];
    }
    $archive = new ZipArchive();
    if ($archive->open($path) !== true) {
        return ['error' => 'Plik nie jest prawidłowym dokumentem Office Open XML.'];
    }

    $metadata = [];
    $parts = [
        'docProps/core.xml' => [
            'creator' => 'author', 'lastModifiedBy' => 'last_modified_by',
            'title' => 'title', 'subject' => 'subject', 'keywords' => 'keywords',
            'description' => 'description', 'created' => 'created', 'modified' => 'modified',
        ],
        'docProps/app.xml' => [
            'Company' => 'company', 'Manager' => 'manager', 'Application' => 'software',
            'TotalTime' => 'editing_time',
        ],
    ];
    foreach ($parts as $entry => $properties) {
        $contents = $archive->getFromName($entry);
        if ($contents === false) {
            continue;
        }
        $xml = @simplexml_load_string($contents, SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOBLANKS);
        if ($xml === false) {
            continue;
        }
        foreach ($properties as $property => $key) {
            $value = xmlProperty($xml, $property);
            if ($key === 'editing_time') {
                $value = formatEditingTime($value);
            }
            addMetadata($metadata, $key, $value);
        }
    }
    $signatureFound = false;
    for ($index = 0; $index < $archive->numFiles; $index++) {
        $entry = $archive->getNameIndex($index);
        if (is_string($entry) && preg_match('~^_xmlsignatures/sig\d+\.xml$~i', $entry)) {
            $signatureFound = true;
            break;
        }
    }
    $archive->close();
    return [
        'metadata' => $metadata,
        'signatures' => $signatureFound ? [
            'status' => 'unsupported',
            'summary' => 'Wykryto podpis XMLDSIG. Weryfikacja podpisów Office nie jest jeszcze obsługiwana.',
            'items' => [],
        ] : null,
    ];
}

function decodePdfDocEncoding(string $value): string
{
    if (preg_match('//u', $value) === 1) {
        return $value;
    }
    $specialCharacters = [
        0x18 => 0x02D8, 0x19 => 0x02C7, 0x1A => 0x02C6, 0x1B => 0x02D9,
        0x1C => 0x02DD, 0x1D => 0x02DB, 0x1E => 0x02DA, 0x1F => 0x02DC,
        0x7F => 0xFFFD, 0x80 => 0x2022, 0x81 => 0x2020, 0x82 => 0x2021,
        0x83 => 0x2026, 0x84 => 0x2014, 0x85 => 0x2013, 0x86 => 0x0192,
        0x87 => 0x2044, 0x88 => 0x2039, 0x89 => 0x203A, 0x8A => 0x2212,
        0x8B => 0x2030, 0x8C => 0x201E, 0x8D => 0x201C, 0x8E => 0x201D,
        0x8F => 0x2018, 0x90 => 0x2019, 0x91 => 0x201A, 0x92 => 0x2122,
        0x93 => 0xFB01, 0x94 => 0xFB02, 0x95 => 0x0141, 0x96 => 0x0152,
        0x97 => 0x0160, 0x98 => 0x0178, 0x99 => 0x017D, 0x9A => 0x0131,
        0x9B => 0x0142, 0x9C => 0x0153, 0x9D => 0x0161, 0x9E => 0x017E,
        0x9F => 0xFFFD, 0xA0 => 0x20AC,
    ];
    $decoded = '';
    for ($index = 0; $index < strlen($value); $index++) {
        $byte = ord($value[$index]);
        $codepoint = $specialCharacters[$byte] ?? $byte;
        $character = iconv('UCS-4BE', 'UTF-8', pack('N', $codepoint));
        $decoded .= $character === false ? "\u{FFFD}" : $character;
    }
    return $decoded;
}

function decodePdfTextBytes(string $value): string
{
    if (str_starts_with($value, "\xFE\xFF")) {
        return (string) iconv('UTF-16BE', 'UTF-8//IGNORE', substr($value, 2));
    }
    if (str_starts_with($value, "\xFF\xFE")) {
        return (string) iconv('UTF-16LE', 'UTF-8//IGNORE', substr($value, 2));
    }
    if (str_starts_with($value, "\xEF\xBB\xBF")) {
        return substr($value, 3);
    }
    return decodePdfDocEncoding($value);
}

function decodePdfString(string $value): string
{
    if (str_starts_with($value, '<')) {
        $decoded = @hex2bin(preg_replace('/\s+/', '', trim($value, '<>')));
        if ($decoded === false) {
            return '';
        }
        return decodePdfTextBytes($decoded);
    }
    $value = substr($value, 1, -1);
    $value = preg_replace_callback('/\\\\([0-7]{1,3}|.)/s', static function (array $match): string {
        $escaped = $match[1];
        if (preg_match('/^[0-7]{1,3}$/', $escaped)) {
            return chr(octdec($escaped));
        }
        return match ($escaped) {
            'n' => "\n", 'r' => "\r", 't' => "\t", 'b' => "\x08", 'f' => "\x0C",
            default => $escaped,
        };
    }, $value);
    return decodePdfTextBytes(str_replace(["\r", "\n"], ' ', $value));
}

function cmsDerLength(string $der): int
{
    if (strlen($der) < 2 || ord($der[0]) !== 0x30) {
        return 0;
    }
    $lengthByte = ord($der[1]);
    if (($lengthByte & 0x80) === 0) {
        return 2 + $lengthByte;
    }
    $lengthBytes = $lengthByte & 0x7f;
    if ($lengthBytes === 0 || $lengthBytes > 4 || strlen($der) < 2 + $lengthBytes) {
        return 0;
    }
    $contentLength = 0;
    for ($index = 0; $index < $lengthBytes; $index++) {
        $contentLength = ($contentLength * 256) + ord($der[2 + $index]);
    }
    return 2 + $lengthBytes + $contentLength;
}

function summarizeCertificate(string $certificate): ?array
{
    $parsed = @openssl_x509_parse($certificate);
    if (!is_array($parsed)) {
        return null;
    }
    $subject = $parsed['subject'] ?? [];
    $issuer = $parsed['issuer'] ?? [];
    $name = $subject['CN'] ?? $subject['O'] ?? $parsed['name'] ?? 'Certyfikat bez nazwy';
    $now = time();
    $validFrom = (int) ($parsed['validFrom_time_t'] ?? 0);
    $validTo = (int) ($parsed['validTo_time_t'] ?? 0);
    return [
        'name' => (string) $name,
        'issuer' => (string) ($issuer['CN'] ?? $issuer['O'] ?? $parsed['issuer'] ?? 'Nieznany wystawca'),
        'valid_from' => $validFrom > 0 ? date('Y-m-d', $validFrom) : 'Nieznana',
        'valid_to' => $validTo > 0 ? date('Y-m-d', $validTo) : 'Nieznana',
        'currently_valid' => $validFrom <= $now && $validTo >= $now,
        'trusted' => @openssl_x509_checkpurpose($certificate, X509_PURPOSE_ANY) === true,
        'fingerprint' => strtoupper((string) openssl_x509_fingerprint($certificate, 'sha256')),
    ];
}

function readDerElement(string $data, int &$offset): ?array
{
    $dataLength = strlen($data);
    if ($offset + 2 > $dataLength) {
        return null;
    }
    $start = $offset;
    $tag = ord($data[$offset++]);
    $lengthByte = ord($data[$offset++]);
    if (($tag & 0x1f) === 0x1f) {
        return null;
    }
    if (($lengthByte & 0x80) === 0) {
        $length = $lengthByte;
    } else {
        $lengthBytes = $lengthByte & 0x7f;
        if ($lengthBytes === 0 || $lengthBytes > 4 || $offset + $lengthBytes > $dataLength) {
            return null;
        }
        $length = 0;
        for ($index = 0; $index < $lengthBytes; $index++) {
            $length = ($length * 256) + ord($data[$offset++]);
        }
    }
    if ($length > $dataLength - $offset) {
        return null;
    }
    $contentOffset = $offset;
    $offset += $length;
    return [
        'tag' => $tag,
        'start' => $start,
        'content' => $contentOffset,
        'length' => $length,
        'end' => $offset,
    ];
}

function derChildren(string $data, array $element): ?array
{
    $offset = $element['content'];
    $children = [];
    while ($offset < $element['end']) {
        $child = readDerElement($data, $offset);
        if ($child === null || $child['end'] > $element['end']) {
            return null;
        }
        $children[] = $child;
    }
    return $offset === $element['end'] ? $children : null;
}

function derObjectIdentifier(string $data, array $element): ?string
{
    if ($element['tag'] !== 0x06 || $element['length'] === 0) {
        return null;
    }
    $bytes = array_values(unpack('C*', substr($data, $element['content'], $element['length'])));
    $arcs = [];
    $value = 0;
    foreach ($bytes as $byte) {
        $value = ($value * 128) + ($byte & 0x7f);
        if (($byte & 0x80) === 0) {
            if ($arcs === []) {
                $firstArc = min(2, intdiv($value, 40));
                $arcs[] = $firstArc;
                $arcs[] = $value - ($firstArc * 40);
            } else {
                $arcs[] = $value;
            }
            $value = 0;
        }
    }
    return $value === 0 ? implode('.', $arcs) : null;
}

function certificateDer(string $certificate): ?string
{
    if (preg_match('~-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----~s', $certificate, $match)) {
        $der = base64_decode(preg_replace('/\s+/', '', $match[1]), true);
        return is_string($der) ? $der : null;
    }
    return isset($certificate[0]) && ord($certificate[0]) === 0x30 ? $certificate : null;
}

function certificateNameDer(string $certificate, string $name): ?string
{
    $der = certificateDer($certificate);
    if (!is_string($der)) {
        return null;
    }
    $offset = 0;
    $certificateElement = readDerElement($der, $offset);
    $certificateFields = $certificateElement !== null ? derChildren($der, $certificateElement) : null;
    $tbs = is_array($certificateFields) ? ($certificateFields[0] ?? null) : null;
    $tbsFields = is_array($tbs) ? derChildren($der, $tbs) : null;
    if (!is_array($tbsFields)) {
        return null;
    }
    $indexOffset = ($tbsFields[0]['tag'] ?? null) === 0xa0 ? 1 : 0;
    $nameIndex = $indexOffset + ($name === 'issuer' ? 2 : 4);
    $nameElement = $tbsFields[$nameIndex] ?? null;
    if (!is_array($nameElement) || $nameElement['tag'] !== 0x30) {
        return null;
    }
    return substr($der, $nameElement['start'], $nameElement['end'] - $nameElement['start']);
}

function fetchValidationResource(string $url): ?string
{
    static $cache = [];
    if (array_key_exists($url, $cache)) {
        return $cache[$url] ?: null;
    }
    if (!function_exists('curl_init') || strlen($url) > 2048) {
        $cache[$url] = false;
        return null;
    }
    $parts = parse_url($url);
    if (!is_array($parts)
        || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)
        || !isset($parts['host'])
        || isset($parts['user'])
        || isset($parts['pass'])) {
        $cache[$url] = false;
        return null;
    }
    $scheme = strtolower($parts['scheme']);
    $host = strtolower(rtrim($parts['host'], '.'));
    $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
    if ($host === '' || $port !== ($scheme === 'https' ? 443 : 80)) {
        $cache[$url] = false;
        return null;
    }
    $hostIsIp = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    $addresses = $hostIsIp
        ? [$host]
        : (gethostbynamel($host) ?: []);
    if ($addresses === []) {
        $cache[$url] = false;
        return null;
    }
    foreach ($addresses as $address) {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            $cache[$url] = false;
            return null;
        }
    }

    $body = '';
    $maxBytes = 8 * 1024 * 1024;
    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROXY => '',
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, $maxBytes): int {
            if (strlen($body) + strlen($chunk) > $maxBytes) {
                return 0;
            }
            $body .= $chunk;
            return strlen($chunk);
        },
    ]);
    if (!$hostIsIp) {
        curl_setopt($curl, CURLOPT_RESOLVE, [$host . ':' . $port . ':' . $addresses[0]]);
    }
    $success = curl_exec($curl) !== false && curl_getinfo($curl, CURLINFO_RESPONSE_CODE) === 200;
    $cache[$url] = $success ? $body : false;
    return $success ? $body : null;
}

function findCertificateIssuer(string $certificate, array $embeddedCertificates): ?string
{
    $issuerName = certificateNameDer($certificate, 'issuer');
    if (!is_string($issuerName)) {
        return null;
    }
    foreach ($embeddedCertificates as $candidate) {
        if (certificateNameDer($candidate, 'subject') === $issuerName
            && @openssl_x509_verify($certificate, $candidate) === 1) {
            return $candidate;
        }
    }
    $parsed = @openssl_x509_parse($certificate);
    $authorityInfo = is_array($parsed) ? (string) ($parsed['extensions']['authorityInfoAccess'] ?? '') : '';
    if (preg_match_all('~CA Issuers\s*-\s*URI:(https?://[^\s,]+)~i', $authorityInfo, $matches)) {
        foreach (array_slice(array_unique($matches[1]), 0, 4) as $url) {
            $data = fetchValidationResource(rtrim($url, '.,;'));
            if (!is_string($data)) {
                continue;
            }
            if (!str_starts_with($data, '-----BEGIN CERTIFICATE-----')) {
                if (!isset($data[0]) || ord($data[0]) !== 0x30) {
                    continue;
                }
                $data = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($data), 64, "\n") . "-----END CERTIFICATE-----\n";
            }
            if (certificateNameDer($data, 'subject') === $issuerName
                && @openssl_x509_verify($certificate, $data) === 1) {
                return $data;
            }
        }
    }
    return null;
}

function trustedListCertificate(string $certificateData): ?string
{
    $der = base64_decode(preg_replace('/\s+/', '', $certificateData), true);
    if (!is_string($der) || $der === '') {
        return null;
    }
    return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
}

function loadPolishTrustedList(): ?array
{
    static $trustedList = null;
    static $loaded = false;
    if ($loaded) {
        return is_array($trustedList) ? $trustedList : null;
    }
    $loaded = true;
    $xml = fetchValidationResource(POLISH_TSL_URL);
    if (!is_string($xml)) {
        $xml = fetchValidationResource('http://www.nccert.pl/tsl/PL_TSL.xml');
    }
    if (!is_string($xml) || !class_exists(DOMDocument::class)) {
        return null;
    }
    $document = new DOMDocument();
    $document->preserveWhiteSpace = true;
    if (!@$document->loadXML($xml, LIBXML_NONET | LIBXML_COMPACT)
        || $document->documentElement?->localName !== 'TrustServiceStatusList') {
        return null;
    }
    $xpath = new DOMXPath($document);
    $signatures = $xpath->query('./*[local-name()="Signature" and namespace-uri()="http://www.w3.org/2000/09/xmldsig#"]', $document->documentElement);
    $signedInfo = $xpath->query('./*[local-name()="SignedInfo"]', $signatures?->item(0));
    $signatureValue = base64_decode(trim($xpath->evaluate('string(./*[local-name()="SignatureValue"])', $signatures?->item(0))), true);
    if ($signatures === false || $signatures->length !== 1 || $signedInfo === false || $signedInfo->length !== 1
        || !is_string($signatureValue)) {
        return null;
    }
    $canonicalizationMethod = trim($xpath->evaluate('string(./*[local-name()="CanonicalizationMethod"]/@Algorithm)', $signedInfo->item(0)));
    $signatureMethod = trim($xpath->evaluate('string(./*[local-name()="SignatureMethod"]/@Algorithm)', $signedInfo->item(0)));
    if ($canonicalizationMethod !== 'http://www.w3.org/2001/10/xml-exc-c14n#'
        || $signatureMethod !== 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512') {
        return null;
    }
    $operatorCertificate = null;
    foreach ($xpath->query('./*[local-name()="KeyInfo"]//*[local-name()="X509Certificate"]', $signatures->item(0)) ?: [] as $certificateNode) {
        $candidate = trustedListCertificate($certificateNode->textContent);
        if ($candidate !== null
            && strtoupper((string) openssl_x509_fingerprint($candidate, 'sha256')) === POLISH_TSL_OPERATOR_FINGERPRINT) {
            $operatorCertificate = $candidate;
            break;
        }
    }
    $operatorInfo = is_string($operatorCertificate) ? @openssl_x509_parse($operatorCertificate) : false;
    if (!is_array($operatorInfo)
        || @openssl_x509_verify($operatorCertificate, $operatorCertificate) !== 1
        || (int) ($operatorInfo['validFrom_time_t'] ?? 0) > time()
        || (int) ($operatorInfo['validTo_time_t'] ?? 0) < time()) {
        return null;
    }
    $references = $xpath->query('./*[local-name()="Reference"]', $signedInfo->item(0));
    if ($references === false || $references->length === 0) {
        return null;
    }
    $documentReferenceVerified = false;
    foreach ($references as $reference) {
        $uri = $reference->getAttribute('URI');
        $digestAlgorithm = trim($xpath->evaluate('string(./*[local-name()="DigestMethod"]/@Algorithm)', $reference));
        $digestValue = base64_decode(trim($xpath->evaluate('string(./*[local-name()="DigestValue"])', $reference)), true);
        $transforms = $xpath->query('./*[local-name()="Transforms"]/*[local-name()="Transform"]', $reference);
        if ($digestAlgorithm !== 'http://www.w3.org/2001/04/xmlenc#sha512'
            || !is_string($digestValue)
            || $transforms === false) {
            return null;
        }
        $transformAlgorithms = [];
        foreach ($transforms as $transform) {
            $transformAlgorithms[] = $transform->getAttribute('Algorithm');
        }
        if ($uri === '') {
            if ($transformAlgorithms !== [
                'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                'http://www.w3.org/2001/10/xml-exc-c14n#',
            ]) {
                return null;
            }
            $referenceDocument = $document->cloneNode(true);
            $referenceXPath = new DOMXPath($referenceDocument);
            $referenceSignatures = $referenceXPath->query('//*[local-name()="Signature" and namespace-uri()="http://www.w3.org/2000/09/xmldsig#"]');
            if ($referenceSignatures === false || $referenceSignatures->length !== 1) {
                return null;
            }
            $referenceSignatures->item(0)->parentNode?->removeChild($referenceSignatures->item(0));
            $referenceNode = $referenceDocument->documentElement;
            $documentReferenceVerified = true;
        } elseif (preg_match('/^#[A-Za-z0-9._:-]+$/', $uri) === 1
            && $transformAlgorithms === ['http://www.w3.org/2001/10/xml-exc-c14n#']) {
            $fragmentId = substr($uri, 1);
            $referenceNode = null;
            $idMatches = 0;
            foreach ($xpath->query('//*[@Id]') ?: [] as $candidateNode) {
                if ($candidateNode instanceof DOMElement && $candidateNode->getAttribute('Id') === $fragmentId) {
                    $referenceNode = $candidateNode;
                    $idMatches++;
                }
            }
            if ($idMatches !== 1 || !$referenceNode instanceof DOMElement) {
                return null;
            }
        } else {
            return null;
        }
        $canonicalReference = $referenceNode->C14N(true, false);
        if (!is_string($canonicalReference)
            || !hash_equals($digestValue, hash('sha512', $canonicalReference, true))) {
            return null;
        }
    }
    $canonicalSignedInfo = $signedInfo->item(0)->C14N(true, false);
    if (!$documentReferenceVerified || !is_string($canonicalSignedInfo)
        || @openssl_verify($canonicalSignedInfo, $signatureValue, $operatorCertificate, OPENSSL_ALGO_SHA512) !== 1) {
        return null;
    }
    $schemeInformation = $xpath->query('//*[local-name()="SchemeInformation"]')->item(0);
    $issueDate = strtotime(trim($xpath->evaluate('string(./*[local-name()="ListIssueDateTime"])', $schemeInformation)));
    $nextUpdate = strtotime(trim($xpath->evaluate('string(./*[local-name()="NextUpdate"])', $schemeInformation)));
    if ($issueDate === false || $nextUpdate === false || $issueDate > time() + 300 || $nextUpdate < time()) {
        return null;
    }
    $roots = [];
    $qualifiedAuthorities = [];
    foreach ($xpath->query('//*[local-name()="TSPService"]/*[local-name()="ServiceInformation"]') ?: [] as $service) {
        $serviceType = trim($xpath->evaluate('string(./*[local-name()="ServiceTypeIdentifier"])', $service));
        $serviceStatus = trim($xpath->evaluate('string(./*[local-name()="ServiceStatus"])', $service));
        $serviceStarting = strtotime(trim($xpath->evaluate('string(./*[local-name()="StatusStartingTime"])', $service)));
        if ($serviceStarting === false || $serviceStarting > time()) {
            continue;
        }
        $isRoot = str_ends_with($serviceType, '/NationalRootCA-QC')
            && in_array($serviceStatus, [
                'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel',
                'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
            ], true);
        $isQualifiedAuthority = str_ends_with($serviceType, '/CA/QC')
            && $serviceStatus === 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
        if ($isQualifiedAuthority) {
            $hasForeSignatures = false;
            $hasQualifiedSignatureCertificates = false;
            $serviceExtensions = $xpath->query('./*[local-name()="ServiceInformationExtensions"]', $service)?->item(0);
            if ($serviceExtensions instanceof DOMElement) {
                foreach ($xpath->query('.//*[local-name()="URI"]', $serviceExtensions) ?: [] as $qualification) {
                    $qualificationUri = trim($qualification->textContent);
                    $hasForeSignatures = $hasForeSignatures
                        || $qualificationUri === 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures';
                }
                foreach ($xpath->query('.//*[local-name()="Qualifier"]', $serviceExtensions) ?: [] as $qualification) {
                    $qualificationUri = trim($qualification->getAttribute('uri'));
                    $hasQualifiedSignatureCertificates = $hasQualifiedSignatureCertificates
                        || $qualificationUri === 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig';
                }
            }
            $isQualifiedAuthority = $hasForeSignatures && $hasQualifiedSignatureCertificates;
        }
        if (!$isRoot && !$isQualifiedAuthority) {
            continue;
        }
        foreach ($xpath->query('./*[local-name()="ServiceDigitalIdentity"]//*[local-name()="X509Certificate"]', $service) ?: [] as $certificateNode) {
            $pem = trustedListCertificate($certificateNode->textContent);
            if ($pem === null || !is_array($parsedCertificate = @openssl_x509_parse($pem))) {
                continue;
            }
            $fingerprint = strtoupper((string) openssl_x509_fingerprint($pem, 'sha256'));
            if ($isRoot
                && (int) ($parsedCertificate['validFrom_time_t'] ?? 0) <= time()
                && (int) ($parsedCertificate['validTo_time_t'] ?? 0) >= time()
                && @openssl_x509_verify($pem, $pem) === 1) {
                $roots[$fingerprint] = $pem;
            } elseif ($isQualifiedAuthority) {
                $qualifiedAuthorities[$fingerprint] = [
                    'certificate' => $pem,
                    'name' => (string) ($parsedCertificate['subject']['CN'] ?? $parsedCertificate['subject']['O'] ?? 'Kwalifikowany urząd certyfikacji'),
                ];
            }
        }
    }
    if ($roots === []) {
        return null;
    }
    $trustedList = [
        'roots' => $roots,
        'qualified_authorities' => $qualifiedAuthorities,
        'sequence' => trim($xpath->evaluate('string(//*[local-name()="TSLSequenceNumber"])')),
        'next_update' => $nextUpdate,
    ];
    return $trustedList;
}

function parseAsn1Time(string $data, array $element): ?int
{
    $value = substr($data, $element['content'], $element['length']);
    if ($element['tag'] === 0x17 && preg_match('/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/', $value, $match)) {
        $year = (int) $match[1];
        $year += $year >= 50 ? 1900 : 2000;
        $value = sprintf('%04d%s%s%s%s%s', $year, $match[2], $match[3], $match[4], $match[5], $match[6]);
        $format = '!YmdHis';
    } elseif ($element['tag'] === 0x18 && preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/', $value, $match)) {
        $value = implode('', array_slice($match, 1));
        $format = '!YmdHis';
    } else {
        return null;
    }
    $date = DateTimeImmutable::createFromFormat($format, $value, new DateTimeZone('UTC'));
    return $date instanceof DateTimeImmutable ? $date->getTimestamp() : null;
}

function verifyCertificateCrl(string $certificate, string $issuerCertificate, string $crlData): ?array
{
    if (preg_match('~-----BEGIN X509 CRL-----(.*?)-----END X509 CRL-----~s', $crlData, $match)) {
        $crlData = base64_decode(preg_replace('/\s+/', '', $match[1]), true) ?: '';
    }
    $crlIssuer = certificateNameDer($issuerCertificate, 'subject');
    if ($crlIssuer === null
        || certificateNameDer($certificate, 'issuer') !== $crlIssuer
        || @openssl_x509_verify($certificate, $issuerCertificate) !== 1) {
        return null;
    }
    $parsedIssuer = @openssl_x509_parse($issuerCertificate);
    $issuerExtensions = is_array($parsedIssuer) ? ($parsedIssuer['extensions'] ?? []) : [];
    $keyUsage = (string) ($issuerExtensions['keyUsage'] ?? '');
    $basicConstraints = (string) ($issuerExtensions['basicConstraints'] ?? '');
    if (($keyUsage !== '' && stripos($keyUsage, 'CRL Sign') === false)
        || ($basicConstraints !== '' && preg_match('/CA:\s*TRUE/i', $basicConstraints) !== 1)) {
        return null;
    }
    $offset = 0;
    $crl = readDerElement($crlData, $offset);
    $crlFields = $crl !== null && $crl['tag'] === 0x30 && $crl['end'] === strlen($crlData)
        ? derChildren($crlData, $crl)
        : null;
    if (!is_array($crlFields) || count($crlFields) !== 3
        || $crlFields[0]['tag'] !== 0x30
        || $crlFields[1]['tag'] !== 0x30
        || $crlFields[2]['tag'] !== 0x03) {
        return null;
    }
    $tbsFields = derChildren($crlData, $crlFields[0]);
    $outerAlgorithm = derChildren($crlData, $crlFields[1]);
    if (!is_array($tbsFields) || !is_array($outerAlgorithm) || $outerAlgorithm === []) {
        return null;
    }
    $index = ($tbsFields[0]['tag'] ?? null) === 0x02 ? 1 : 0;
    $innerAlgorithm = $tbsFields[$index] ?? null;
    $issuerName = $tbsFields[$index + 1] ?? null;
    $thisUpdate = $tbsFields[$index + 2] ?? null;
    if (!is_array($innerAlgorithm) || !is_array($issuerName) || !is_array($thisUpdate)
        || $issuerName['tag'] !== 0x30
        || !hash_equals($crlIssuer, substr($crlData, $issuerName['start'], $issuerName['end'] - $issuerName['start']))) {
        return null;
    }
    $innerAlgorithmFields = derChildren($crlData, $innerAlgorithm);
    $algorithmOid = derObjectIdentifier($crlData, $outerAlgorithm[0]);
    if (!is_array($innerAlgorithmFields) || $algorithmOid === null
        || derObjectIdentifier($crlData, $innerAlgorithmFields[0]) !== $algorithmOid) {
        return null;
    }
    $signatureAlgorithm = match ($algorithmOid) {
        '1.2.840.113549.1.1.5', '1.2.840.10045.4.1', '1.2.840.10040.4.3' => OPENSSL_ALGO_SHA1,
        '1.2.840.113549.1.1.11', '1.2.840.10045.4.3.2', '2.16.840.1.101.3.4.3.2' => OPENSSL_ALGO_SHA256,
        '1.2.840.113549.1.1.12', '1.2.840.10045.4.3.3' => OPENSSL_ALGO_SHA384,
        '1.2.840.113549.1.1.13', '1.2.840.10045.4.3.4' => OPENSSL_ALGO_SHA512,
        default => null,
    };
    $signatureBits = $crlFields[2];
    if ($signatureAlgorithm === null || $signatureBits['length'] < 2
        || ord($crlData[$signatureBits['content']]) !== 0) {
        return null;
    }
    $crlExtensions = [];
    for ($fieldIndex = $index + 3; $fieldIndex < count($tbsFields); $fieldIndex++) {
        if ($tbsFields[$fieldIndex]['tag'] === 0xa0) {
            $explicit = derChildren($crlData, $tbsFields[$fieldIndex]);
            $crlExtensions = is_array($explicit) && isset($explicit[0]) ? derChildren($crlData, $explicit[0]) ?? [] : [];
            break;
        }
    }
    foreach ($crlExtensions as $extension) {
        $fields = derChildren($crlData, $extension);
        $oid = is_array($fields) && isset($fields[0]) ? derObjectIdentifier($crlData, $fields[0]) : null;
        if (in_array($oid, ['2.5.29.27', '2.5.29.28'], true)) {
            return null;
        }
        if (($fields[1]['tag'] ?? null) === 0x01
            && substr($crlData, $fields[1]['content'], $fields[1]['length']) !== "\0") {
            return null;
        }
    }
    $nextUpdate = null;
    $revokedCertificates = null;
    for ($fieldIndex = $index + 3; $fieldIndex < count($tbsFields); $fieldIndex++) {
        $field = $tbsFields[$fieldIndex];
        if (in_array($field['tag'], [0x17, 0x18], true) && $nextUpdate === null) {
            $nextUpdate = parseAsn1Time($crlData, $field);
        } elseif ($field['tag'] === 0x30) {
            $entries = derChildren($crlData, $field);
            if (is_array($entries) && isset($entries[0]) && $entries[0]['tag'] === 0x30) {
                $firstEntry = derChildren($crlData, $entries[0]);
                if (is_array($firstEntry) && ($firstEntry[0]['tag'] ?? null) === 0x02) {
                    $revokedCertificates = $entries;
                }
            }
        }
    }
    $thisTimestamp = parseAsn1Time($crlData, $thisUpdate);
    if ($thisTimestamp === null || $nextUpdate === null
        || $thisTimestamp > time() + 300 || $nextUpdate < time()) {
        return null;
    }
    $tbsBytes = substr($crlData, $crlFields[0]['start'], $crlFields[0]['end'] - $crlFields[0]['start']);
    $signature = substr($crlData, $signatureBits['content'] + 1, $signatureBits['length'] - 1);
    if (@openssl_verify($tbsBytes, $signature, $issuerCertificate, $signatureAlgorithm) !== 1) {
        return null;
    }
    $parsedCertificate = @openssl_x509_parse($certificate);
    $serialNumber = (string) ($parsedCertificate['serialNumberHex'] ?? '');
    if ($serialNumber === '') {
        return null;
    }
    $serial = strtoupper(ltrim($serialNumber, '0')) ?: '0';
    foreach ($revokedCertificates ?? [] as $entry) {
        $entryFields = derChildren($crlData, $entry);
        if (!is_array($entryFields) || ($entryFields[0]['tag'] ?? null) !== 0x02) {
            return null;
        }
        if (($entryFields[2]['tag'] ?? null) === 0x30) {
            foreach (derChildren($crlData, $entryFields[2]) ?? [] as $extension) {
                $fields = derChildren($crlData, $extension);
                $oid = is_array($fields) && isset($fields[0]) ? derObjectIdentifier($crlData, $fields[0]) : null;
                if ($oid === '2.5.29.29'
                    || (($fields[1]['tag'] ?? null) === 0x01
                        && substr($crlData, $fields[1]['content'], $fields[1]['length']) !== "\0")) {
                    return null;
                }
            }
        }
        $entrySerial = strtoupper(ltrim(bin2hex(substr($crlData, $entryFields[0]['content'], $entryFields[0]['length'])), '0')) ?: '0';
        if ($entrySerial === $serial) {
            $revokedAt = isset($entryFields[1]) ? parseAsn1Time($crlData, $entryFields[1]) : null;
            return $revokedAt !== null && $revokedAt > time()
                ? ['status' => 'good', 'message' => 'Nie figuruje na aktualnej liście CRL.', 'source' => '']
                : ['status' => 'revoked', 'message' => 'Certyfikat znajduje się na aktualnej liście CRL.', 'source' => ''];
        }
    }
    return ['status' => 'good', 'message' => 'Nie figuruje na aktualnej, poprawnie podpisanej liście CRL.', 'source' => ''];
}

function certificateRevocationStatus(string $certificate, array $embeddedCertificates): array
{
    $parsed = @openssl_x509_parse($certificate);
    $distributionPoints = is_array($parsed) ? (string) ($parsed['extensions']['crlDistributionPoints'] ?? '') : '';
    if (!preg_match_all('~URI:(https?://[^\s,]+)~i', $distributionPoints, $matches)) {
        return ['status' => 'unknown', 'message' => 'Certyfikat nie zawiera adresu CRL.', 'source' => ''];
    }
    $issuerCertificate = findCertificateIssuer($certificate, $embeddedCertificates);
    if (!is_string($issuerCertificate)) {
        return ['status' => 'unknown', 'message' => 'Nie udało się zweryfikować certyfikatu wystawcy.', 'source' => ''];
    }
    $lastSource = '';
    $goodStatus = null;
    foreach (array_slice(array_unique(array_map(static fn (string $url): string => rtrim($url, '.,;'), $matches[1])), 0, 4) as $url) {
        $lastSource = $url;
        $crlData = fetchValidationResource($url);
        if (!is_string($crlData)) {
            continue;
        }
        $status = verifyCertificateCrl($certificate, $issuerCertificate, $crlData);
        if (is_array($status)) {
            $status['source'] = $url;
            if ($status['status'] === 'revoked') {
                return $status;
            }
            $goodStatus ??= $status;
        }
    }
    if (is_array($goodStatus)) {
        return $goodStatus;
    }
    return [
        'status' => 'unknown',
        'message' => 'Nie udało się pobrać lub zweryfikować aktualnej listy CRL.',
        'source' => $lastSource,
    ];
}

function validateCertificateChain(string $certificate, array $embeddedCertificates): array
{
    $trustedList = loadPolishTrustedList();
    if (!is_array($trustedList)) {
        return [
            'status' => 'unknown',
            'message' => 'Nie udało się zweryfikować podpisanej polskiej listy TSL.',
            'certificates' => [],
        ];
    }
    $certificatePool = array_merge($embeddedCertificates, array_values($trustedList['roots']));
    $chain = [];
    $seenFingerprints = [];
    $current = $certificate;
    $rootCertificate = null;
    for ($depth = 0; $depth < 8; $depth++) {
        $fingerprint = strtoupper((string) openssl_x509_fingerprint($current, 'sha256'));
        if ($fingerprint === '' || isset($seenFingerprints[$fingerprint])) {
            break;
        }
        $seenFingerprints[$fingerprint] = true;
        $chain[] = $current;
        if (isset($trustedList['roots'][$fingerprint])) {
            $rootCertificate = $current;
            break;
        }
        $issuerCertificate = findCertificateIssuer($current, $certificatePool);
        if (!is_string($issuerCertificate)) {
            break;
        }
        $certificatePool[] = $issuerCertificate;
        $current = $issuerCertificate;
    }
    if (!is_string($rootCertificate)) {
        return [
            'status' => 'unknown',
            'message' => 'Nie udało się zbudować łańcucha do aktywnego korzenia z polskiej TSL.',
            'certificates' => array_map(static function (string $chainCertificate, int $index) use ($chain): array {
                $parsed = @openssl_x509_parse($chainCertificate);
                return [
                    'name' => (string) (($parsed['subject']['CN'] ?? null) ?: ($parsed['subject']['O'] ?? 'Certyfikat')),
                    'role' => $index === 0 ? 'Podpisujący' : 'Urząd pośredni',
                    'fingerprint' => strtoupper((string) openssl_x509_fingerprint($chainCertificate, 'sha256')),
                ];
            }, $chain, array_keys($chain)),
        ];
    }
    $rootFingerprint = strtoupper((string) openssl_x509_fingerprint($rootCertificate, 'sha256'));
    $rootPath = tempnam(sys_get_temp_dir(), 'metadata-root-');
    $intermediatesPath = tempnam(sys_get_temp_dir(), 'metadata-chain-');
    if ($rootPath === false || $intermediatesPath === false) {
        if (is_string($rootPath)) {
            @unlink($rootPath);
        }
        if (is_string($intermediatesPath)) {
            @unlink($intermediatesPath);
        }
        return ['status' => 'unknown', 'message' => 'Nie udało się przygotować weryfikacji łańcucha.', 'certificates' => []];
    }
    $intermediateCertificates = array_slice($chain, 1, -1);
    $filesWritten = file_put_contents($rootPath, $rootCertificate) !== false
        && file_put_contents($intermediatesPath, implode("\n", $intermediateCertificates)) !== false;
    $pathTrusted = false;
    if ($filesWritten) {
        $untrustedPath = $intermediateCertificates === [] ? null : $intermediatesPath;
        $pathTrusted = @openssl_x509_checkpurpose($certificate, X509_PURPOSE_ANY, [$rootPath], $untrustedPath) === true;
    }
    @unlink($rootPath);
    @unlink($intermediatesPath);
    if (!$pathTrusted) {
        return ['status' => 'invalid', 'message' => 'OpenSSL odrzucił łańcuch certyfikatów (podpis, ważność lub ograniczenia CA).', 'certificates' => []];
    }
    $authority = $chain[1] ?? $rootCertificate;
    $authorityFingerprint = strtoupper((string) openssl_x509_fingerprint($authority, 'sha256'));
    $qualifiedAuthority = isset($trustedList['qualified_authorities'][$authorityFingerprint]);
    $certificateStatuses = [];
    $hasUnknownRevocation = false;
    $hasRevokedCertificate = false;
    foreach ($chain as $index => $chainCertificate) {
        $parsed = @openssl_x509_parse($chainCertificate);
        $isRoot = $index === count($chain) - 1;
        $revocation = $isRoot
            ? ['status' => 'good', 'message' => 'Korzeń znajduje się na aktualnej polskiej TSL.', 'source' => POLISH_TSL_URL]
            : certificateRevocationStatus($chainCertificate, $chain);
        $hasUnknownRevocation = $hasUnknownRevocation || $revocation['status'] === 'unknown';
        $hasRevokedCertificate = $hasRevokedCertificate || $revocation['status'] === 'revoked';
        $certificateStatuses[] = [
            'name' => (string) (($parsed['subject']['CN'] ?? null) ?: ($parsed['subject']['O'] ?? 'Certyfikat')),
            'role' => $index === 0 ? 'Podpisujący' : ($isRoot ? 'Korzeń' : 'Sub-CA'),
            'fingerprint' => strtoupper((string) openssl_x509_fingerprint($chainCertificate, 'sha256')),
            'revocation' => $revocation,
        ];
    }
    if (!$qualifiedAuthority) {
        return [
            'status' => 'not_qualified',
            'message' => 'Ścieżka dochodzi do korzenia TSL, ale wystawca podpisującego nie ma aktywnego wpisu CA/QC.',
            'certificates' => $certificateStatuses,
        ];
    }
    if ($hasRevokedCertificate) {
        return [
            'status' => 'revoked',
            'message' => 'Co najmniej jeden certyfikat w łańcuchu figuruje na aktualnej CRL.',
            'certificates' => $certificateStatuses,
        ];
    }
    if ($hasUnknownRevocation) {
        return [
            'status' => 'unknown',
            'message' => 'Łańcuch jest poprawny, ale nie udało się zweryfikować CRL dla każdego certyfikatu.',
            'certificates' => $certificateStatuses,
        ];
    }
    return [
        'status' => 'valid',
        'message' => 'Pełny łańcuch prowadzi do aktywnego korzenia NCCert; wystawca ma status CA/QC w TSL, a CRL są aktualne.',
        'certificates' => $certificateStatuses,
    ];
}

function verifyPdfSignatures(string $contents): array
{
    preg_match_all('~/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]~', $contents, $ranges, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
    if ($ranges === []) {
        return ['status' => 'none', 'summary' => 'Nie znaleziono osadzonego podpisu cyfrowego PDF.', 'items' => []];
    }
    if (!function_exists('openssl_cms_verify') || !function_exists('openssl_pkcs7_read')) {
        return ['status' => 'unavailable', 'summary' => 'Weryfikacja podpisów PDF wymaga rozszerzenia PHP OpenSSL.', 'items' => []];
    }

    $items = [];
    foreach ($ranges as $rangeMatch) {
        $range = array_map('intval', array_column(array_slice($rangeMatch, 1), 0));
        $signatureContent = [];
        $validRange = count($range) === 4
            && $range[0] === 0
            && $range[1] >= 0
            && $range[2] > $range[1]
            && $range[3] >= 0
            && $range[2] + $range[3] <= strlen($contents);

        if ($validRange) {
            $gap = substr($contents, $range[1], $range[2] - $range[1]);
            if (!preg_match('~^\s*<([\da-fA-F\s]+)>\s*$~s', $gap, $signatureContent, PREG_OFFSET_CAPTURE)) {
                $validRange = false;
            }
        }
        if (!$validRange || $signatureContent === []) {
            $validRange = false;
        }
        $cms = '';
        if ($signatureContent !== []) {
            $contentsMatch = $signatureContent[0][0];
            $hex = preg_replace('/\s+/', '', $signatureContent[1][0]);
            $decoded = $hex !== '' ? @hex2bin($hex) : false;
            $derLength = is_string($decoded) ? cmsDerLength($decoded) : 0;
            if (is_string($decoded) && $derLength > 0 && $derLength <= strlen($decoded)) {
                $cms = substr($decoded, 0, $derLength);
            } else {
                $validRange = false;
            }
        } else {
            $validRange = false;
        }

        $signatureValid = false;
        $certificates = [];
        if ($cms !== '') {
            $pem = "-----BEGIN PKCS7-----\n" . chunk_split(base64_encode($cms), 64, "\n") . "-----END PKCS7-----\n";
            $certificatePems = [];
            if (@openssl_pkcs7_read($pem, $certificatePems)) {
                $signerFingerprints = [];
                foreach ($certificatePems as $candidate) {
                    $candidateSubject = certificateNameDer($candidate, 'subject');
                    $isIssuer = false;
                    foreach ($certificatePems as $child) {
                        if ($candidate === $child || certificateNameDer($child, 'issuer') !== $candidateSubject) {
                            continue;
                        }
                        if (@openssl_x509_verify($child, $candidate) === 1) {
                            $isIssuer = true;
                            break;
                        }
                    }
                    if (!$isIssuer) {
                        $fingerprint = strtoupper((string) openssl_x509_fingerprint($candidate, 'sha256'));
                        if ($fingerprint !== '') {
                            $signerFingerprints[$fingerprint] = true;
                        }
                    }
                }
                $chainReports = [];
                $chainRevocations = [];
                foreach ($certificatePems as $candidate) {
                    $fingerprint = strtoupper((string) openssl_x509_fingerprint($candidate, 'sha256'));
                    if (!isset($signerFingerprints[$fingerprint])) {
                        continue;
                    }
                    $chainReport = validateCertificateChain($candidate, $certificatePems);
                    $chainReports[$fingerprint] = $chainReport;
                    foreach ($chainReport['certificates'] as $chainCertificate) {
                        if (isset($chainCertificate['revocation'])) {
                            $chainRevocations[$chainCertificate['fingerprint']] = $chainCertificate['revocation'];
                        }
                    }
                }
                foreach ($certificatePems as $certificatePem) {
                    $summary = summarizeCertificate($certificatePem);
                    if ($summary !== null) {
                        $summary['revocation'] = $chainRevocations[$summary['fingerprint']]
                            ?? certificateRevocationStatus($certificatePem, $certificatePems);
                        if (isset($chainReports[$summary['fingerprint']])) {
                            $summary['chain'] = $chainReports[$summary['fingerprint']];
                        }
                        $certificates[] = $summary;
                    }
                }
            }
        }
        if ($validRange && $cms !== '') {
            $signatureFile = tempnam(sys_get_temp_dir(), 'metadata-cms-');
            $contentFile = tempnam(sys_get_temp_dir(), 'metadata-signed-');
            if ($signatureFile !== false && $contentFile !== false) {
                $signedContent = substr($contents, $range[0], $range[1]) . substr($contents, $range[2], $range[3]);
                if (file_put_contents($signatureFile, $cms) !== false && file_put_contents($contentFile, $signedContent) !== false) {
                    $flags = OPENSSL_CMS_BINARY | OPENSSL_CMS_DETACHED | OPENSSL_CMS_NOVERIFY;
                    $signatureValid = @openssl_cms_verify(
                        $contentFile,
                        $flags,
                        null,
                        [],
                        null,
                        null,
                        null,
                        $signatureFile,
                        OPENSSL_ENCODING_DER
                    ) === true;
                }
            }
            if (is_string($signatureFile)) {
                @unlink($signatureFile);
            }
            if (is_string($contentFile)) {
                @unlink($contentFile);
            }
        }

        $items[] = [
            'valid' => $signatureValid,
            'summary' => $signatureValid
                ? 'Podpis kryptograficzny poprawny.'
                : 'Podpis niepoprawny lub dane objęte podpisem zostały zmienione.',
            'certificates' => $certificates,
        ];
    }
    $validCount = count(array_filter($items, static fn (array $item): bool => $item['valid']));
    return [
        'status' => $validCount === count($items) ? 'valid' : 'invalid',
        'summary' => $validCount . ' z ' . count($items) . ' podpisów ma poprawną integralność kryptograficzną.',
        'items' => $items,
    ];
}

function expandPdfObjectStreams(string $contents): string
{
    $expanded = '';
    $offset = 0;
    while (($objectStreamOffset = strpos($contents, '/ObjStm', $offset)) !== false) {
        $streamOffset = strpos($contents, 'stream', $objectStreamOffset);
        if ($streamOffset === false) {
            break;
        }
        $streamStart = $streamOffset + strlen('stream');
        if (substr($contents, $streamStart, 2) === "\r\n") {
            $streamStart += 2;
        } elseif (substr($contents, $streamStart, 1) === "\n" || substr($contents, $streamStart, 1) === "\r") {
            $streamStart++;
        }
        $streamEnd = strpos($contents, 'endstream', $streamStart);
        if ($streamEnd === false) {
            break;
        }
        $dictionaryStart = strrpos(substr($contents, 0, $objectStreamOffset), '<<');
        $dictionary = $dictionaryStart !== false
            ? substr($contents, $dictionaryStart, $streamOffset - $dictionaryStart)
            : '';
        $compressed = rtrim(substr($contents, $streamStart, $streamEnd - $streamStart), "\r\n");
        if (preg_match('~/Filter\s*(?:\[\s*)?/FlateDecode\b~', $dictionary)) {
            $stream = @gzuncompress($compressed);
        } else {
            $stream = $compressed;
        }
        if (is_string($stream)) {
            $expanded .= "\n" . $stream;
        }
        $offset = $streamEnd + strlen('endstream');
    }
    return $expanded === '' ? $contents : $contents . $expanded;
}

function extractPdfMetadata(string $path): array
{
    $contents = file_get_contents($path);
    if ($contents === false || !str_starts_with($contents, '%PDF-')) {
        return ['error' => 'Plik nie wygląda na prawidłowy dokument PDF.'];
    }
    $metadata = [];
    $properties = [
        'Author' => 'author', 'Title' => 'title', 'Subject' => 'subject',
        'Keywords' => 'keywords', 'Creator' => 'software', 'Producer' => 'producer',
        'CreationDate' => 'created', 'ModDate' => 'modified',
    ];
    $searchableContents = expandPdfObjectStreams($contents);
    foreach ($properties as $property => $key) {
        $pattern = '~/' . preg_quote($property, '~') . '\s*(\((?:\\\\.|[^\\\\)])*\)|<[\da-fA-F\s]+>)~s';
        if (preg_match($pattern, $searchableContents, $match)) {
            addMetadata($metadata, $key, decodePdfString($match[1]));
        }
    }
    return ['metadata' => $metadata, 'signatures' => verifyPdfSignatures($contents)];
}

function flattenExif(array $data, array &$metadata): void
{
    $mapping = [
        'artist' => 'author', 'copyright' => 'copyright', 'imagedescription' => 'description',
        'datetimeoriginal' => 'created', 'datetime' => 'modified', 'make' => 'camera',
        'model' => 'camera', 'software' => 'software',
    ];
    foreach ($data as $key => $value) {
        if (is_array($value)) {
            flattenExif($value, $metadata);
            continue;
        }
        $key = strtolower((string) $key);
        if (!isset($mapping[$key])) {
            continue;
        }
        $metadataKey = $mapping[$key];
        if ($metadataKey === 'camera' && isset($metadata[$metadataKey])) {
            addMetadata($metadata, $metadataKey, $metadata[$metadataKey] . ' ' . (string) $value);
        } else {
            addMetadata($metadata, $metadataKey, $value);
        }
    }
}

function extractImageMetadata(string $path): array
{
    if (!function_exists('exif_read_data')) {
        return ['error' => 'Odczyt metadanych obrazów wymaga rozszerzenia PHP EXIF.'];
    }
    $metadata = [];
    $exif = @exif_read_data($path, null, true);
    if (is_array($exif)) {
        flattenExif($exif, $metadata);
    }
    return ['metadata' => $metadata];
}

function inspectFile(string $path, string $name): array
{
    $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (in_array($extension, ['jpg', 'jpeg', 'tif', 'tiff'], true)) {
        $image = @getimagesize($path);
        if ($image === false || !in_array($image[2], [IMAGETYPE_JPEG, IMAGETYPE_TIFF_II, IMAGETYPE_TIFF_MM], true)) {
            return ['error' => 'Plik nie jest prawidłowym obrazem JPEG lub TIFF.'];
        }
        return extractImageMetadata($path);
    }
    if ($extension === 'pdf') {
        return extractPdfMetadata($path);
    }
    if (in_array($extension, ['docx', 'xlsx', 'pptx'], true)) {
        return extractOfficeMetadata($path);
    }
    return ['error' => 'Nieobsługiwany format. Wybierz PDF, DOCX, XLSX, PPTX, JPG lub TIFF.'];
}

function normalizedValue(string $value): string
{
    $value = preg_replace('/\s+/u', ' ', trim($value)) ?? trim($value);
    return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
}

$results = [];
$comparisons = [];
$formError = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string) ($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        $formError = 'Sesja formularza wygasła. Odśwież stronę i spróbuj ponownie.';
    } elseif (!isset($_FILES['files']) || !is_array($_FILES['files']['name'] ?? null)) {
        $formError = 'Wybierz co najmniej jeden plik do analizy.';
    } else {
        $files = $_FILES['files'];
        $fileCount = count($files['name']);
        if ($fileCount > MAX_FILES) {
            $formError = 'Jednorazowo można sprawdzić maksymalnie ' . MAX_FILES . ' plików.';
        } else {
            for ($index = 0; $index < $fileCount; $index++) {
                $name = basename((string) $files['name'][$index]);
                $error = (int) $files['error'][$index];
                if ($error === UPLOAD_ERR_NO_FILE) {
                    continue;
                }
                if ($error !== UPLOAD_ERR_OK) {
                    $results[] = ['name' => $name, 'error' => 'Nie udało się przesłać pliku (kod ' . $error . ').', 'metadata' => []];
                    continue;
                }
                if ((int) $files['size'][$index] > MAX_FILE_SIZE) {
                    $results[] = ['name' => $name, 'error' => 'Plik przekracza limit 20 MB.', 'metadata' => []];
                    continue;
                }
                $inspection = inspectFile((string) $files['tmp_name'][$index], $name);
                $results[] = [
                    'name' => $name,
                    'error' => $inspection['error'] ?? '',
                    'metadata' => $inspection['metadata'] ?? [],
                    'signatures' => $inspection['signatures'] ?? null,
                ];
            }
            if ($results === []) {
                $formError = 'Wybierz co najmniej jeden plik do analizy.';
            }
            for ($left = 0; $left < count($results); $left++) {
                for ($right = $left + 1; $right < count($results); $right++) {
                    if ($results[$left]['error'] !== '' || $results[$right]['error'] !== '') {
                        continue;
                    }
                    $matches = [];
                    foreach ($results[$left]['metadata'] as $key => $value) {
                        if (isset($results[$right]['metadata'][$key])
                            && normalizedValue($value) === normalizedValue($results[$right]['metadata'][$key])) {
                            $matches[$key] = $value;
                        }
                    }
                    if ($matches !== []) {
                        $comparisons[] = ['left' => $left, 'right' => $right, 'matches' => $matches];
                    }
                }
            }
        }
    }
}
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f5f4ee">
    <title>Ślad Metadanych</title>
    <link rel="stylesheet" href="app.css">
</head>
<body>
<main class="shell">
    <header class="topbar">
        <a class="brand" href="./" aria-label="Ślad Metadanych, strona główna">
            <span class="brand-mark" aria-hidden="true"><span></span><span></span><span></span></span>
            <span>Ślad<span class="brand-light">Metadanych</span></span>
        </a>
        <span class="privacy-note"><span class="status-dot"></span> Analiza lokalna <span class="build-version">v<?= escape($version) ?></span></span>
    </header>
    <section class="intro">
        <p class="eyebrow">ANALIZA PLIKÓW / 01</p>
        <h1>Co plik mówi<br><span>o swoim pochodzeniu?</span></h1>
        <p class="intro-copy">Odczytaj zapisane informacje i sprawdź, które dokumenty łączy autor, firma lub inne wspólne dane.</p>
    </section>
    <section class="workspace" aria-label="Analiza metadanych">
        <div class="section-heading"><div><p class="eyebrow">NOWA ANALIZA</p><h2>Dodaj pliki do porównania</h2></div><span class="format-note">PDF · Office · JPG · TIFF</span></div>
        <?php if ($formError !== ''): ?><div class="notice notice-error" role="alert"><?= escape($formError) ?></div><?php endif; ?>
        <form method="post" enctype="multipart/form-data" class="upload-form">
            <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
            <label class="dropzone" for="files">
                <span class="upload-symbol" aria-hidden="true">+</span>
                <span class="drop-copy"><strong>Wybierz pliki</strong><span>lub przeciągnij je tutaj</span></span>
                <span class="drop-limit">Do 10 plików, maks. 20 MB każdy</span>
                <input id="files" name="files[]" type="file" multiple accept=".pdf,.docx,.xlsx,.pptx,.jpg,.jpeg,.tif,.tiff">
            </label>
            <div class="form-actions"><p id="file-summary" class="file-summary">Nie wybrano plików</p><button class="analyze-button" type="submit"><span>Sprawdź metadane</span><span aria-hidden="true">↗</span></button></div>
        </form>
        <?php if ($results !== []): ?>
            <section class="results" aria-live="polite">
                <div class="results-heading"><div><p class="eyebrow">WYNIK ANALIZY</p><h2><?= count($results) ?> <?= count($results) === 1 ? 'plik' : 'plików' ?></h2></div><span class="result-caption">Metadane dostępne w przesłanych plikach</span></div>
                <?php if ($comparisons !== []): ?>
                    <div class="matches">
                        <div class="matches-title"><span class="match-icon" aria-hidden="true">=</span><strong>Znaleziono wspólne dane</strong></div>
                        <?php foreach ($comparisons as $comparison): ?>
                            <div class="match-row">
                                <div class="match-files"><span><?= escape($results[$comparison['left']]['name']) ?></span><span class="match-arrow" aria-hidden="true">↔</span><span><?= escape($results[$comparison['right']]['name']) ?></span></div>
                                <div class="match-values">
                                    <?php foreach ($comparison['matches'] as $key => $value): ?>
                                        <span class="match-chip <?= in_array($key, ['author', 'company'], true) ? 'match-important' : '' ?>"><b><?= escape($labels[$key] ?? $key) ?>:</b> <?= escape($value) ?></span>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php elseif (count($results) > 1): ?>
                    <div class="notice notice-neutral">Nie znaleziono identycznych, niepustych wartości metadanych między poprawnie odczytanymi plikami.</div>
                <?php endif; ?>
                <div class="file-results">
                    <?php foreach ($results as $result): ?>
                        <article class="file-result">
                            <div class="file-heading"><span class="file-type" aria-hidden="true"><?= escape(strtoupper(pathinfo($result['name'], PATHINFO_EXTENSION))) ?></span><div class="file-name-wrap"><h3><?= escape($result['name']) ?></h3><p><?= $result['error'] !== '' ? 'Nie udało się odczytać' : count($result['metadata']) . ' odczytanych pól' ?></p></div><span class="file-state <?= $result['error'] !== '' ? 'state-error' : '' ?>" aria-label="<?= $result['error'] !== '' ? 'Błąd' : 'Przeanalizowano' ?>"></span></div>
                            <?php if ($result['error'] !== ''): ?><p class="file-error"><?= escape($result['error']) ?></p>
                            <?php elseif ($result['metadata'] === []): ?><p class="empty-metadata">Ten plik nie zawiera odczytywalnych metadanych.</p>
                            <?php else: ?><dl class="metadata-list"><?php foreach ($result['metadata'] as $key => $value): ?><div><dt><?= escape($labels[$key] ?? $key) ?></dt><dd><?= escape($value) ?></dd></div><?php endforeach; ?></dl><?php endif; ?>
                            <?php if (is_array($result['signatures'])): ?>
                                <div class="signature-report">
                                    <div class="signature-heading"><strong>Podpis cyfrowy</strong><span class="signature-status status-<?= escape($result['signatures']['status']) ?>"><?= escape($result['signatures']['summary']) ?></span></div>
                                    <?php foreach ($result['signatures']['items'] as $signatureIndex => $signature): ?>
                                        <div class="signature-item">
                                            <p>Podpis <?= $signatureIndex + 1 ?>: <?= escape($signature['summary']) ?></p>
                                            <?php if ($signature['certificates'] === []): ?><p>Nie udało się odczytać certyfikatu z bloku podpisu.</p><?php endif; ?>
                                            <?php foreach ($signature['certificates'] as $certificate): ?>
                                                <dl class="certificate-list">
                                                    <div><dt>Podpisujący</dt><dd><?= escape($certificate['name']) ?></dd></div>
                                                    <div><dt>Wystawca</dt><dd><?= escape($certificate['issuer']) ?></dd></div>
                                                    <div><dt>Ważność</dt><dd><?= escape($certificate['valid_from']) ?> – <?= escape($certificate['valid_to']) ?> · <?= $certificate['currently_valid'] ? 'ważny obecnie' : 'poza okresem ważności' ?></dd></div>
                                                    <div><dt>Zaufanie lokalne</dt><dd><?= $certificate['trusted'] ? 'certyfikat zaufany przez lokalny magazyn OpenSSL' : 'certyfikat niezaufany lub niezweryfikowany przez lokalny magazyn OpenSSL' ?></dd></div>
                                                    <div><dt>Status CRL</dt><dd><?= escape($certificate['revocation']['message']) ?><?php if ($certificate['revocation']['source'] !== ''): ?> · <a href="<?= escape($certificate['revocation']['source']) ?>" rel="noopener noreferrer" target="_blank">źródło CRL</a><?php endif; ?></dd></div>
                                                    <?php if (isset($certificate['chain'])): ?><div><dt>Łańcuch zaufania</dt><dd><strong class="chain-status-<?= escape($certificate['chain']['status']) ?>"><?= escape($certificate['chain']['message']) ?></strong><?php if ($certificate['chain']['certificates'] !== []): ?><ol class="certificate-chain-path"><?php foreach ($certificate['chain']['certificates'] as $chainCertificate): ?><li><?= escape($chainCertificate['role']) ?>: <?= escape($chainCertificate['name']) ?><?php if (isset($chainCertificate['revocation'])): ?> · <?= escape($chainCertificate['revocation']['message']) ?><?php if ($chainCertificate['revocation']['source'] !== ''): ?> · <a href="<?= escape($chainCertificate['revocation']['source']) ?>" rel="noopener noreferrer" target="_blank">źródło</a><?php endif; ?><?php endif; ?></li><?php endforeach; ?></ol><?php endif; ?></dd></div><?php endif; ?>
                                                    <div><dt>SHA-256</dt><dd><?= escape($certificate['fingerprint']) ?></dd></div>
                                                </dl>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endforeach; ?>
                                    <?php if ($result['signatures']['status'] !== 'none'): ?><p class="signature-caveat">Integralność podpisu, łańcuch certyfikatów i zaufanie lokalne to odrębne wyniki. Łańcuch jest sprawdzany względem podpisanej polskiej TSL i CRL wskazanych przez kolejne certyfikaty; OCSP nie jest obsługiwane.</p><?php endif; ?>
                                </div>
                            <?php endif; ?>
                        </article>
                    <?php endforeach; ?>
                </div>
            </section>
        <?php endif; ?>
    </section>
    <footer class="page-footer"><span>INFORMACJA O PRYWATNOŚCI</span>Pliki są analizowane w pamięci serwera i nie są zapisywane na dysku aplikacji.</footer>
</main>
<script>
const fileInput = document.getElementById('files');
const fileSummary = document.getElementById('file-summary');
const dropzone = document.querySelector('.dropzone');
fileInput.addEventListener('change', () => {
    const count = fileInput.files.length;
    fileSummary.textContent = count === 0 ? 'Nie wybrano plików' : `Wybrano plików: ${count}`;
});
for (const eventName of ['dragenter', 'dragover']) {
    dropzone.addEventListener(eventName, event => {
        event.preventDefault();
        dropzone.classList.add('is-dragging');
    });
}
for (const eventName of ['dragleave', 'drop']) {
    dropzone.addEventListener(eventName, event => {
        event.preventDefault();
        dropzone.classList.remove('is-dragging');
    });
}
dropzone.addEventListener('drop', event => {
    if (event.dataTransfer.files.length) {
        fileInput.files = event.dataTransfer.files;
        fileInput.dispatchEvent(new Event('change'));
    }
});
</script>
</body>
</html>