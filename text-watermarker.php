<?php
declare(strict_types=1);

/**
 * TEXT Watermarker - single file payload embedder.
 *
 * The companion of LLM Sanitizer. Hides an arbitrary string inside cover text
 * using the same three carriers the sanitizer decodes, so a round trip is exact:
 *
 *   variation selectors  U+FE00-FE0F (byte 0..15), U+E0100-E01EF (byte 16..255)
 *   tag characters       U+E0020-E007E = printable ASCII, plus U+E0001 start
 *   zero width binary    U+200B = 0, U+200C = 1, eight bits per byte
 *
 * The visible wording of the cover text never changes. This is a research and
 * fixture generation tool: use it to watermark your own content, to produce test
 * cases for the sanitizer, or to show people what an invisible payload looks like
 * in a hex view. It cannot and does not touch anyone else's text.
 *
 * Usage:
 *   web : drop the file on any PHP 7.4+ host and open it in a browser
 *   cli : php text-watermarker.php --secret="hello" < cover.txt > out.txt
 *         php text-watermarker.php --carrier=tag --secret="id=42" --at=end < cover.txt
 *         echo "cover" | php text-watermarker.php --carrier=zw --secret="hi"
 *         php text-watermarker.php --decode < out.txt        (read a payload back)
 *
 * No Composer, no ext-mbstring. ext-intl not needed.
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Rolid spol. s r.o.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

final class LlmWatermarker
{
    public const VERSION = '1.0.0';

    public const CARRIERS = ['vs', 'tag', 'zw'];
    public const POSITIONS = ['first', 'end', 'marker'];

    // ------------------------------------------------------------- encoding

    /**
     * Encode a UTF-8 secret into a run of carrier characters.
     */
    public static function encode(string $secret, string $carrier): string
    {
        switch ($carrier) {
            case 'vs':  return self::encVs($secret);
            case 'tag': return self::encTag($secret);
            case 'zw':  return self::encZw($secret);
        }
        throw new InvalidArgumentException('unknown carrier: ' . $carrier);
    }

    /** One byte per selector: 0..15 -> FE00.., 16..255 -> E0100.. */
    private static function encVs(string $secret): string
    {
        $out = '';
        foreach (unpack('C*', $secret) ?: [] as $b) {
            $out .= self::uchr($b <= 15 ? 0xFE00 + $b : 0xE0100 + $b - 16);
        }
        return $out;
    }

    /** Printable ASCII copied into the tag block. Non-ASCII bytes are skipped. */
    private static function encTag(string $secret): string
    {
        $out = '';
        $len = strlen($secret);
        for ($i = 0; $i < $len; $i++) {
            $c = ord($secret[$i]);
            if ($c >= 0x20 && $c <= 0x7E) { $out .= self::uchr(0xE0000 + $c); }
        }
        return $out;
    }

    /** Each bit becomes a zero width character, MSB first, eight per byte. */
    private static function encZw(string $secret): string
    {
        $out = '';
        foreach (unpack('C*', $secret) ?: [] as $b) {
            for ($i = 7; $i >= 0; $i--) {
                $out .= self::uchr(($b >> $i) & 1 ? 0x200C : 0x200B);
            }
        }
        return $out;
    }

    /**
     * Insert an already encoded payload into cover text at a chosen position.
     * 'first'  after the first visible (non-space) character
     * 'end'    appended at the very end
     * 'marker' replacing the first occurrence of $marker
     */
    public static function inject(string $cover, string $payload, string $pos, string $marker = ''): string
    {
        if ($payload === '') { return $cover; }

        if ($pos === 'end') {
            // keep the payload before a single trailing newline if present
            if (substr($cover, -1) === "\n") { return substr($cover, 0, -1) . $payload . "\n"; }
            return $cover . $payload;
        }

        if ($pos === 'marker' && $marker !== '') {
            $at = strpos($cover, $marker);
            if ($at !== false) {
                $at += strlen($marker);
                return substr($cover, 0, $at) . $payload . substr($cover, $at);
            }
            // marker not found, fall through to 'first'
        }

        // 'first': attach after the first character that is not whitespace,
        // so a variation selector always has a real base to bind to
        if (preg_match('/^(\s*\X)/u', $cover, $m)) {
            $head = $m[1];
            return $head . $payload . substr($cover, strlen($head));
        }
        return $payload . $cover;
    }

    public static function embed(
        string $cover,
        string $secret,
        string $carrier,
        string $pos = 'first',
        string $marker = ''
    ): string {
        return self::inject($cover, self::encode($secret, $carrier), $pos, $marker);
    }

    // ------------------------------------------------------------- decoding

    /**
     * Read every payload back out of a text. Mirrors the sanitizer's decoder.
     * @return array<int,array{carrier:string,payload:string}>
     */
    public static function decode(string $s): array
    {
        $found = [];
        if (preg_match_all('/[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]+/u', $s, $m)) {
            foreach ($m[0] as $run) {
                $bytes = '';
                foreach (self::chars($run) as $ch) {
                    $cp = self::uord($ch);
                    $bytes .= chr($cp <= 0xFE0F ? $cp - 0xFE00 : $cp - 0xE0100 + 16);
                }
                $found[] = ['carrier' => 'vs', 'payload' => $bytes];
            }
        }
        if (preg_match_all('/[\x{E0001}\x{E0020}-\x{E007F}]+/u', $s, $m)) {
            foreach ($m[0] as $run) {
                $txt = '';
                foreach (self::chars($run) as $ch) {
                    $cp = self::uord($ch);
                    if ($cp >= 0xE0020 && $cp <= 0xE007E) { $txt .= chr($cp - 0xE0000); }
                }
                if ($txt !== '') { $found[] = ['carrier' => 'tag', 'payload' => $txt]; }
            }
        }
        if (preg_match_all('/[\x{200B}\x{200C}]{8,}/u', $s, $m)) {
            foreach ($m[0] as $run) {
                $bits = '';
                foreach (self::chars($run) as $ch) {
                    $bits .= self::uord($ch) === 0x200C ? '1' : '0';
                }
                $whole = intdiv(strlen($bits), 8) * 8;
                if ($whole >= 8) {
                    $txt = '';
                    foreach (str_split(substr($bits, 0, $whole), 8) as $b) {
                        $txt .= chr((int)bindec($b));
                    }
                    $found[] = ['carrier' => 'zw', 'payload' => $txt];
                }
            }
        }
        return $found;
    }

    // -------------------------------------------------------------- helpers

    public static function overhead(string $secret, string $carrier): int
    {
        return strlen(self::encode($secret, $carrier));
    }

    public static function ulen(string $s): int
    {
        return (int)preg_match_all('/./us', $s);
    }

    /** @return array<int,string> */
    private static function chars(string $s): array
    {
        return preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    private static function uord(string $ch): int
    {
        $b = unpack('C*', $ch);
        if (!$b) { return 0; }
        $b = array_values($b);
        switch (count($b)) {
            case 1: return $b[0];
            case 2: return (($b[0] & 0x1F) << 6) | ($b[1] & 0x3F);
            case 3: return (($b[0] & 0x0F) << 12) | (($b[1] & 0x3F) << 6) | ($b[2] & 0x3F);
            case 4: return (($b[0] & 0x07) << 18) | (($b[1] & 0x3F) << 12)
                         | (($b[2] & 0x3F) << 6) | ($b[3] & 0x3F);
        }
        return 0;
    }

    private static function uchr(int $cp): string
    {
        if ($cp < 0x80)    { return chr($cp); }
        if ($cp < 0x800)   { return chr(0xC0 | $cp >> 6) . chr(0x80 | $cp & 0x3F); }
        if ($cp < 0x10000) { return chr(0xE0 | $cp >> 12) . chr(0x80 | ($cp >> 6) & 0x3F)
                                  . chr(0x80 | $cp & 0x3F); }
        return chr(0xF0 | $cp >> 18) . chr(0x80 | ($cp >> 12) & 0x3F)
             . chr(0x80 | ($cp >> 6) & 0x3F) . chr(0x80 | $cp & 0x3F);
    }
}

/* ------------------------------------------------------------------ i18n */

final class W18n
{
    public const LANGS = ['en' => 'English', 'de' => 'Deutsch', 'es' => 'Español',
                          'cs' => 'Čeština', 'ja' => '日本語'];

    private const S = [
'en' => [
 'tagline' => 'Hides an arbitrary string inside cover text using invisible carriers. The visible wording never changes. Round trips exactly with LLM Sanitizer. A research and fixture tool, nothing is stored or sent anywhere.',
 'cover' => 'Cover text', 'secret' => 'Secret to hide', 'output' => 'Output with payload',
 'carrier' => 'Carrier', 'position' => 'Position', 'marker' => 'Marker string', 'uilang' => 'Interface',
 'embed' => 'Embed', 'copy' => 'Copy output', 'chars' => 'characters', 'bytes' => 'bytes overhead',
 'verify' => 'Round trip check', 'verify_ok' => 'Decoded back cleanly, payload matches.',
 'verify_fail' => 'Round trip mismatch, decoded:', 'hexview' => 'Hex view of the output',
 'placeholder_cover' => 'Text that will be shown to the reader...',
 'placeholder_secret' => 'Name, ID, timestamp, anything...',
 'c_vs' => 'Variation selectors (1 char per byte, needs a base letter)',
 'c_tag' => 'Tag characters (ASCII only, no base needed)',
 'c_zw' => 'Zero width binary (8 chars per byte)',
 'p_first' => 'After the first visible character', 'p_end' => 'At the very end',
 'p_marker' => 'After a marker string',
 'note' => 'This embeds into text you provide, for watermarking your own content and for building test cases. It does not defeat AI labelling: under the EU AI Act an AI disclosure must be visible to the reader, not hidden in invisible characters. Use LLM Sanitizer to strip payloads back out.',
 'empty' => 'Enter a secret to embed.',
],
'de' => [
 'tagline' => 'Versteckt eine beliebige Zeichenkette in einem Trägertext mit unsichtbaren Trägern. Der sichtbare Wortlaut ändert sich nie. Exakter Rücklauf mit LLM Sanitizer. Ein Forschungs- und Testwerkzeug, nichts wird gespeichert oder übertragen.',
 'cover' => 'Trägertext', 'secret' => 'Zu versteckendes Geheimnis', 'output' => 'Ausgabe mit Nutzlast',
 'carrier' => 'Träger', 'position' => 'Position', 'marker' => 'Markierungstext', 'uilang' => 'Oberfläche',
 'embed' => 'Einbetten', 'copy' => 'Ausgabe kopieren', 'chars' => 'Zeichen', 'bytes' => 'Byte Mehraufwand',
 'verify' => 'Rücklaufprüfung', 'verify_ok' => 'Sauber zurückgelesen, Nutzlast stimmt überein.',
 'verify_fail' => 'Rücklauf weicht ab, gelesen:', 'hexview' => 'Hex-Ansicht der Ausgabe',
 'placeholder_cover' => 'Text, der dem Leser angezeigt wird...',
 'placeholder_secret' => 'Name, ID, Zeitstempel, beliebig...',
 'c_vs' => 'Variantenselektoren (1 Zeichen pro Byte, braucht einen Grundbuchstaben)',
 'c_tag' => 'Tag-Zeichen (nur ASCII, kein Grundzeichen nötig)',
 'c_zw' => 'Nullbreite binär (8 Zeichen pro Byte)',
 'p_first' => 'Nach dem ersten sichtbaren Zeichen', 'p_end' => 'Ganz am Ende',
 'p_marker' => 'Nach einem Markierungstext',
 'note' => 'Bettet in von Ihnen bereitgestellten Text ein, zum Wasserzeichnen eigener Inhalte und zum Erstellen von Testfällen. Es umgeht keine KI-Kennzeichnung: nach dem EU AI Act muss ein KI-Hinweis für den Leser sichtbar sein, nicht in unsichtbaren Zeichen versteckt. Nutzen Sie LLM Sanitizer, um Nutzlasten zu entfernen.',
 'empty' => 'Geben Sie ein Geheimnis zum Einbetten ein.',
],
'es' => [
 'tagline' => 'Oculta una cadena arbitraria dentro de un texto portador mediante portadores invisibles. La redacción visible nunca cambia. Ida y vuelta exacta con LLM Sanitizer. Herramienta de investigación y pruebas, no se guarda ni se envía nada.',
 'cover' => 'Texto portador', 'secret' => 'Secreto a ocultar', 'output' => 'Salida con carga',
 'carrier' => 'Portador', 'position' => 'Posición', 'marker' => 'Cadena marcadora', 'uilang' => 'Interfaz',
 'embed' => 'Incrustar', 'copy' => 'Copiar salida', 'chars' => 'caracteres', 'bytes' => 'bytes de sobrecarga',
 'verify' => 'Comprobación de ida y vuelta', 'verify_ok' => 'Descodificado sin problemas, la carga coincide.',
 'verify_fail' => 'Discrepancia de ida y vuelta, descodificado:', 'hexview' => 'Vista hex de la salida',
 'placeholder_cover' => 'Texto que verá el lector...',
 'placeholder_secret' => 'Nombre, ID, marca de tiempo, lo que sea...',
 'c_vs' => 'Selectores de variación (1 carácter por byte, necesita una letra base)',
 'c_tag' => 'Caracteres de etiqueta (solo ASCII, sin base)',
 'c_zw' => 'Binario de ancho cero (8 caracteres por byte)',
 'p_first' => 'Tras el primer carácter visible', 'p_end' => 'Al final del todo',
 'p_marker' => 'Tras una cadena marcadora',
 'note' => 'Incrusta en texto que tú aportas, para poner marca de agua a tu propio contenido y crear casos de prueba. No elude el etiquetado de IA: según el Reglamento de IA de la UE, la divulgación de IA debe ser visible para el lector, no oculta en caracteres invisibles. Usa LLM Sanitizer para retirar las cargas.',
 'empty' => 'Introduce un secreto para incrustar.',
],
'cs' => [
 'tagline' => 'Schova libovolny retezec do nosneho textu pomoci neviditelnych nosicu. Viditelny obsah se nemeni. Presny round trip s LLM Sanitizer. Nastroj na vyzkum a testy, nic se neuklada ani neodesila.',
 'cover' => 'Nosny text', 'secret' => 'Co schovat', 'output' => 'Vystup s payloadem',
 'carrier' => 'Nosic', 'position' => 'Umisteni', 'marker' => 'Znacka', 'uilang' => 'Rozhrani',
 'embed' => 'Vlozit', 'copy' => 'Kopirovat vystup', 'chars' => 'znaku', 'bytes' => 'bajtu navic',
 'verify' => 'Kontrola round trip', 'verify_ok' => 'Zpetne precteno v poradku, payload sedi.',
 'verify_fail' => 'Round trip nesedi, precteno:', 'hexview' => 'Hex nahled vystupu',
 'placeholder_cover' => 'Text, ktery uvidi ctenar...',
 'placeholder_secret' => 'Jmeno, ID, casove razitko, cokoli...',
 'c_vs' => 'Variation selectors (1 znak na bajt, potrebuje nosne pismeno)',
 'c_tag' => 'Tag characters (jen ASCII, bez nosneho znaku)',
 'c_zw' => 'Zero width binarne (8 znaku na bajt)',
 'p_first' => 'Za prvni viditelny znak', 'p_end' => 'Uplne na konec',
 'p_marker' => 'Za znacku v textu',
 'note' => 'Vklada do textu, ktery zadas ty, pro znaceni vlastniho obsahu a stavbu testu. Neobchazi to oznacovani AI: podle AI Actu ma byt oznaceni AI viditelne pro ctenare, ne schovane v neviditelnych znacich. Na odstraneni payloadu pouzij LLM Sanitizer.',
 'empty' => 'Zadej retezec, ktery se ma vlozit.',
],
'ja' => [
 'tagline' => '任意の文字列を不可視の担体でカバーテキストに隠します。見た目の文章は変わりません。LLM Sanitizer と正確に往復できます。研究とテスト用のツールで、データの保存も送信も行いません。',
 'cover' => 'カバーテキスト', 'secret' => '隠す文字列', 'output' => 'ペイロード入りの出力',
 'carrier' => '担体', 'position' => '挿入位置', 'marker' => '目印文字列', 'uilang' => '表示言語',
 'embed' => '埋め込む', 'copy' => '出力をコピー', 'chars' => '文字', 'bytes' => 'バイトの追加分',
 'verify' => '往復チェック', 'verify_ok' => '正しくデコードできました。ペイロードは一致しています。',
 'verify_fail' => '往復が一致しません。デコード結果:', 'hexview' => '出力の16進表示',
 'placeholder_cover' => '読者に見せるテキスト...',
 'placeholder_secret' => '名前、ID、タイムスタンプなど...',
 'c_vs' => '異体字セレクタ (1バイトにつき1文字、基底文字が必要)',
 'c_tag' => 'タグ文字 (ASCII のみ、基底文字は不要)',
 'c_zw' => 'ゼロ幅バイナリ (1バイトにつき8文字)',
 'p_first' => '最初の可視文字の直後', 'p_end' => '末尾',
 'p_marker' => '目印文字列の直後',
 'note' => 'あなたが入力したテキストに埋め込みます。自分のコンテンツへの電子透かしやテストケースの作成に使ってください。AI の表示義務は回避できません。EU AI Act では AI の開示は読者に見える形で行う必要があり、不可視文字に隠してはいけません。ペイロードの除去には LLM Sanitizer を使ってください。',
 'empty' => '埋め込む文字列を入力してください。',
],
    ];

    public static function t(string $lang, string $key): string
    {
        return self::S[$lang][$key] ?? self::S['en'][$key] ?? $key;
    }

    public static function detect(): string
    {
        if (isset($_GET['lang']) && isset(self::LANGS[(string)$_GET['lang']])) { return (string)$_GET['lang']; }
        if (isset($_COOKIE['lls_lang']) && isset(self::LANGS[(string)$_COOKIE['lls_lang']])) {
            return (string)$_COOKIE['lls_lang'];
        }
        foreach (explode(',', (string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')) as $part) {
            $code = strtolower(trim(explode(';', $part)[0]));
            $code = str_replace(['cs-cz', 'cz'], 'cs', $code);
            $short = substr($code, 0, 2);
            if (isset(self::LANGS[$short])) { return $short; }
        }
        return 'en';
    }
}

/* -------------------------------------------------------------------- CLI */

if (PHP_SAPI === 'cli') {
    $carrier = 'vs';
    $secret = null;
    $pos = 'first';
    $marker = '';
    $decodeOnly = false;
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--decode') { $decodeOnly = true; }
        elseif ($a === '--version') { echo 'LLM Watermarker ' . LlmWatermarker::VERSION . " (MIT)\n"; exit(0); }
        elseif ($a === '--help' || $a === '-h') {
            fwrite(STDERR, "LLM Watermarker " . LlmWatermarker::VERSION . " - MIT\n"
                . "usage: php llm-watermarker.php --secret=STR [--carrier=vs|tag|zw]\n"
                . "       [--at=first|end|marker] [--marker=STR] < cover.txt > out.txt\n"
                . "       php llm-watermarker.php --decode < out.txt\n"
                . "carriers: vs = variation selectors, tag = tag characters, zw = zero width binary\n");
            exit(0);
        }
        elseif (strpos($a, '--carrier=') === 0) { $carrier = substr($a, 10); }
        elseif (strpos($a, '--secret=') === 0)  { $secret = substr($a, 9); }
        elseif (strpos($a, '--at=') === 0)      { $pos = substr($a, 5); }
        elseif (strpos($a, '--marker=') === 0)  { $marker = substr($a, 9); }
    }
    $in = (string)stream_get_contents(STDIN);

    if ($decodeOnly) {
        foreach (LlmWatermarker::decode($in) as $d) {
            fwrite(STDERR, "[{$d['carrier']}] " . addcslashes($d['payload'], "\0..\37\177..\377") . "\n");
        }
        exit(0);
    }
    if (!in_array($carrier, LlmWatermarker::CARRIERS, true)) {
        fwrite(STDERR, "unknown carrier: $carrier\n"); exit(2);
    }
    if ($secret === null || $secret === '') {
        fwrite(STDERR, "missing --secret, see --help\n"); exit(2);
    }
    $out = LlmWatermarker::embed($in, $secret, $carrier, $pos, $marker);
    echo $out;

    // round trip check to stderr, so stdout stays clean
    $ok = false;
    foreach (LlmWatermarker::decode($out) as $d) {
        if ($d['carrier'] === $carrier && $d['payload'] === $secret) { $ok = true; break; }
    }
    fwrite(STDERR, $ok ? "round trip ok\n" : "round trip FAILED\n");
    exit($ok ? 0 : 1);
}

/* -------------------------------------------------------------------- web */

$lang = W18n::detect();
if (isset($_POST['uilang']) && isset(W18n::LANGS[(string)$_POST['uilang']])) { $lang = (string)$_POST['uilang']; }
if (!headers_sent()) {
    setcookie('lls_lang', $lang, ['expires' => time() + 31536000, 'path' => '/', 'samesite' => 'Lax']);
}

$posted  = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
$cover   = (string)($_POST['cover'] ?? '');
$secret  = (string)($_POST['secret'] ?? '');
$carrier = (string)($_POST['carrier'] ?? 'vs');
$pos     = (string)($_POST['position'] ?? 'first');
$marker  = (string)($_POST['marker'] ?? '');
if (!in_array($carrier, LlmWatermarker::CARRIERS, true)) { $carrier = 'vs'; }
if (!in_array($pos, LlmWatermarker::POSITIONS, true)) { $pos = 'first'; }

$result = '';
$verify = null;
$overhead = 0;
if ($posted && $secret !== '') {
    $result = LlmWatermarker::embed($cover, $secret, $carrier, $pos, $marker);
    $overhead = LlmWatermarker::overhead($secret, $carrier);
    foreach (LlmWatermarker::decode($result) as $d) {
        if ($d['carrier'] === $carrier) { $verify = $d['payload']; break; }
    }
}

function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function t(string $k): string { global $lang; return W18n::t($lang, $k); }

$hex = '';
if ($result !== '') {
    $hex = trim(chunk_split(strtoupper(bin2hex($result)), 2, ' '));
    if (strlen($hex) > 1400) { $hex = substr($hex, 0, 1400) . ' ...'; }
}
?><!doctype html>
<html lang="<?= h($lang) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>LLM Watermarker</title>
<style>
:root { color-scheme: dark; --bg:#12141a; --fg:#e6e8ee; --mut:#8b93a7; --acc:#e8a33d;
        --ok:#7dd3a0; --err:#e86d6d; --line:#262a35; --panel:#0c0e13 }
* { box-sizing:border-box }
body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
       font:15px/1.55 ui-sans-serif,system-ui,"Segoe UI","Noto Sans JP",Roboto,sans-serif }
.wrap { max-width:1180px; margin:0 auto }
header { display:flex; flex-wrap:wrap; align-items:baseline; gap:12px; justify-content:space-between }
h1 { font-size:20px; margin:0; letter-spacing:-.01em }
h1 span { color:var(--mut); font-weight:400; font-size:12px; margin-left:8px }
p.sub { color:var(--mut); margin:6px 0 18px; font-size:13px; max-width:82ch }
.cols { display:grid; grid-template-columns:1fr 1fr; gap:16px }
@media (max-width:900px){ .cols{grid-template-columns:1fr} }
textarea { width:100%; height:200px; padding:12px; background:var(--panel); color:var(--fg);
           border:1px solid var(--line); border-radius:8px; resize:vertical;
           font:13px/1.5 ui-monospace,"Cascadia Code",Consolas,"Noto Sans Mono CJK JP",monospace;
           white-space:pre-wrap }
input[type=text] { width:100%; padding:9px 12px; background:var(--panel); color:var(--fg);
           border:1px solid var(--line); border-radius:8px; font:13px ui-monospace,Consolas,monospace }
select { background:var(--panel); color:var(--fg); border:1px solid var(--line);
         border-radius:6px; padding:6px 8px; font-size:13px; width:100% }
label.lbl { display:block; color:var(--mut); font-size:12px; margin:0 0 4px }
.grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin:12px 0 }
@media (max-width:700px){ .grid3{grid-template-columns:1fr} }
button { background:var(--acc); color:#0c0e13; border:0; border-radius:8px; padding:10px 20px;
         font-weight:600; cursor:pointer; font-size:14px }
button.ghost { background:transparent; color:var(--fg); border:1px solid var(--line); font-weight:500 }
.bar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin:14px 0 }
.sel { display:flex; gap:6px; align-items:center; font-size:12px; color:var(--mut) }
.card { border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin:12px 0 }
.card.ok { border-color:var(--ok) } .card.err { border-color:var(--err) }
.card h3 { margin:0 0 6px; font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--mut) }
code { font:12px ui-monospace,Consolas,monospace; background:var(--panel); padding:1px 5px; border-radius:4px;
       word-break:break-all }
.mut { color:var(--mut) } .ok { color:var(--ok) } .err { color:var(--err) }
footer { margin-top:22px; font-size:12px; color:var(--mut); border-top:1px solid var(--line); padding-top:12px }
a { color:var(--acc) }
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>LLM Watermarker <span>v<?= h(LlmWatermarker::VERSION) ?> &middot; MIT</span></h1>
  <form method="post" id="langform" class="sel">
    <input type="hidden" name="cover" value="<?= h($cover) ?>">
    <input type="hidden" name="secret" value="<?= h($secret) ?>">
    <input type="hidden" name="carrier" value="<?= h($carrier) ?>">
    <input type="hidden" name="position" value="<?= h($pos) ?>">
    <input type="hidden" name="marker" value="<?= h($marker) ?>">
    <label class="mut" for="uilang"><?= h(t('uilang')) ?></label>
    <select id="uilang" name="uilang" style="width:auto" onchange="document.getElementById('langform').submit()">
      <?php foreach (W18n::LANGS as $code => $name): ?>
        <option value="<?= h($code) ?>" <?= $code === $lang ? 'selected' : '' ?>><?= h($name) ?></option>
      <?php endforeach; ?>
    </select>
  </form>
</header>
<p class="sub"><?= h(t('tagline')) ?></p>

<form method="post" id="main">
  <input type="hidden" name="uilang" value="<?= h($lang) ?>">
  <div class="cols">
    <div>
      <label class="lbl" for="cover"><?= h(t('cover')) ?></label>
      <textarea id="cover" name="cover" placeholder="<?= h(t('placeholder_cover')) ?>"><?= h($cover) ?></textarea>
    </div>
    <div>
      <label class="lbl" for="out"><?= h(t('output')) ?></label>
      <textarea id="out" readonly><?= h($result) ?></textarea>
    </div>
  </div>

  <div style="margin-top:12px">
    <label class="lbl" for="secret"><?= h(t('secret')) ?></label>
    <input type="text" id="secret" name="secret" value="<?= h($secret) ?>"
           placeholder="<?= h(t('placeholder_secret')) ?>">
  </div>

  <div class="grid3">
    <div>
      <label class="lbl" for="carrier"><?= h(t('carrier')) ?></label>
      <select id="carrier" name="carrier" onchange="toggleMarker()">
        <option value="vs"  <?= $carrier === 'vs'  ? 'selected' : '' ?>><?= h(t('c_vs')) ?></option>
        <option value="tag" <?= $carrier === 'tag' ? 'selected' : '' ?>><?= h(t('c_tag')) ?></option>
        <option value="zw"  <?= $carrier === 'zw'  ? 'selected' : '' ?>><?= h(t('c_zw')) ?></option>
      </select>
    </div>
    <div>
      <label class="lbl" for="position"><?= h(t('position')) ?></label>
      <select id="position" name="position" onchange="toggleMarker()">
        <option value="first"  <?= $pos === 'first'  ? 'selected' : '' ?>><?= h(t('p_first')) ?></option>
        <option value="end"    <?= $pos === 'end'    ? 'selected' : '' ?>><?= h(t('p_end')) ?></option>
        <option value="marker" <?= $pos === 'marker' ? 'selected' : '' ?>><?= h(t('p_marker')) ?></option>
      </select>
    </div>
    <div id="markerbox">
      <label class="lbl" for="marker"><?= h(t('marker')) ?></label>
      <input type="text" id="marker" name="marker" value="<?= h($marker) ?>">
    </div>
  </div>

  <div class="bar">
    <button type="submit"><?= h(t('embed')) ?></button>
    <button type="button" class="ghost"
      onclick="navigator.clipboard.writeText(document.getElementById('out').value)"><?= h(t('copy')) ?></button>
    <?php if ($posted && $secret === ''): ?><span class="err" style="font-size:12px"><?= h(t('empty')) ?></span><?php endif; ?>
    <?php if ($result !== ''): ?>
      <span class="mut" style="font-size:12px">
        <?= h(LlmWatermarker::ulen($cover) . ' -> ' . LlmWatermarker::ulen($result) . ' ' . t('chars')
             . ', +' . $overhead . ' ' . t('bytes')) ?>
      </span>
    <?php endif; ?>
  </div>
</form>

<?php if ($result !== ''): ?>
  <?php $ok = $verify === $secret; ?>
  <div class="card <?= $ok ? 'ok' : 'err' ?>">
    <h3><?= h(t('verify')) ?></h3>
    <?php if ($ok): ?>
      <span class="ok"><?= h(t('verify_ok')) ?></span> <code><?= h($secret) ?></code>
    <?php else: ?>
      <span class="err"><?= h(t('verify_fail')) ?></span>
      <code><?= h((string)preg_replace('/[^\x20-\x7E]/', '.', (string)$verify)) ?></code>
    <?php endif; ?>
  </div>
  <div class="card">
    <h3><?= h(t('hexview')) ?></h3>
    <code><?= h($hex) ?></code>
  </div>
<?php endif; ?>

<footer>
  <p><?= h(t('note')) ?></p>
  <p>CLI: <code>php llm-watermarker.php --carrier=<?= h($carrier) ?> --secret="..." &lt; cover.txt &gt; out.txt</code>
     &middot; <code>--decode</code> &middot; <code>--help</code></p>
  <p>LLM Watermarker v<?= h(LlmWatermarker::VERSION) ?>, MIT License, (c) 2026 Rolid spol. s r.o.</p>
</footer>
</div>
<script>
function toggleMarker() {
  var isMarker = document.getElementById('position').value === 'marker';
  document.getElementById('markerbox').style.opacity = isMarker ? '1' : '.35';
  document.getElementById('marker').disabled = !isMarker;
}
toggleMarker();
</script>
</body>
</html>
