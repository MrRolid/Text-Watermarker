# Text Watermarker

Single file PHP tool that hides an arbitrary string inside cover text using
invisible Unicode carriers. The visible wording of the text never changes, so
what a reader sees is identical before and after. What changes is the byte
stream: a payload rides along in characters that no editor renders.

No Composer, no `ext-mbstring`, no database, nothing stored or sent anywhere.
Drop the file on any PHP 7.4+ host and open it, or pipe text through it on the
command line. Web UI in English, German, Spanish, Czech and Japanese.

> This is a research and fixture tool. It embeds into text **you** provide, for
> watermarking your own content, building forensic trails, or generating test
> cases. It does not and cannot touch anyone else's text. See
> [Responsible use](#responsible-use) before you reach for it.

## What it does

Given cover text and a secret, it produces an identical looking string with the
secret woven in. Given a watermarked string, it reads the secret back out. The
encoder and decoder are exact inverses, so a round trip returns the original
bytes.

```
$ echo "The quarterly report is attached." \
    | php llm-watermarker.php --secret="doc=Q3;user=martin"
The quarterly report is attached.

$ echo "The quarterly report is attached." \
    | php llm-watermarker.php --secret="doc=Q3;user=martin" \
    | php llm-watermarker.php --decode
[vs] doc=Q3;user=martin
```

The two lines of output look the same. The first one carries eighteen hidden
characters after the letter `T`.

## Carriers

Three encodings, each with different trade-offs. Pick with `--carrier`.

| Carrier | Flag | Cost per byte | Needs a base char | Payload range |
| --- | --- | --- | --- | --- |
| Variation selectors | `vs` | 1 char (4 bytes UTF-8) | yes | any byte, so any UTF-8 string |
| Tag characters | `tag` | 1 char (4 bytes UTF-8) | no | printable ASCII only |
| Zero width binary | `zw` | 8 chars | no | any byte |

**Variation selectors** map one byte onto one selector: `U+FE00-FE0F` for byte
values 0 to 15, `U+E0100-E01EF` for 16 to 255. Selectors bind to the preceding
character, so the payload needs a base letter to attach to. This is the densest
carrier for arbitrary data and survives most copy-paste paths.

**Tag characters** are a one-to-one copy of printable ASCII shifted into the
`U+E0000` block, so `A` becomes `U+E0041`. They render as nothing and need no
base character, which means they can sit between two spaces. ASCII payloads only.

**Zero width binary** encodes each bit as `U+200B` (0) or `U+200C` (1), most
significant bit first, eight per byte. It is the bulkiest option at eight
characters per byte, but it uses the most widely recognised zero width points.

The secret is treated as raw UTF-8 bytes, so `vs` and `zw` happily carry
accents, emoji, or anything else. Round trip of `café→🔑` comes back byte exact.

## Placement

Where the payload lands, set with `--at`.

- `first` (default) attaches the run after the first visible character, so a
  variation selector always has a real base to bind to.
- `end` appends the run at the very end, before a single trailing newline if
  one is present, so the file does not end in invisible bytes past the line break.
- `marker` inserts the run right after the first occurrence of `--marker=STR`.
  Useful for template stamping, for example placing a per-recipient token right
  after a `NAME` placeholder. Falls back to `first` if the marker is absent.

## Command line

```
php llm-watermarker.php --secret="STR" [--carrier=vs|tag|zw]
                        [--at=first|end|marker] [--marker=STR] < cover.txt > out.txt

php llm-watermarker.php --decode < out.txt
php llm-watermarker.php --help
php llm-watermarker.php --version
```

The watermarked text goes to stdout. The round trip self-check and any decode
output go to stderr, so a pipe stays clean. The exit code is `0` when the
embedded payload reads back intact and `1` when it does not, which makes the
tool usable as a test assertion:

```
php llm-watermarker.php --secret="$TOKEN" < cover.txt > out.txt || echo "round trip failed"
```

## Web interface

Open the file in a browser and you get a two pane editor: cover text on the
left, watermarked result on the right, with the secret, carrier, position and
marker below. Every embed runs a round trip check and shows a pass or fail card,
plus a hex view of the output so you can see exactly which bytes were added.
Nothing leaves the browser tab beyond the single POST to the same script;
nothing is stored server side.

The interface language follows `?lang=xx`, then a cookie, then the browser
`Accept-Language` header, defaulting to English. Supported: `en`, `de`, `es`,
`cs`, `ja`.

## How it survives, and how it does not

A payload made of these characters is durable in some paths and fragile in
others, which is worth understanding before you rely on it.

Survives: copy and paste between most applications, because the clipboard carries
codepoints; email, JSON, and databases stored as `utf8mb4`; pasting into many CMS
editors.

Does not survive: retyping by hand; any pipeline that normalises text to a
restricted character set; a determined strip of invisible characters. A
sanitizer that removes exactly these carriers will erase the payload completely,
which is the point of having both directions.

Variation selectors and tag characters share a UTF-8 prefix worth remembering:
every codepoint in the `U+E0000` plane starts with the two bytes `F3 A0`, so
`hexdump -C out.txt | grep -i 'f3 a0'` reveals both carriers with no regex
support at all.

## Requirements

- PHP 7.4 or newer with PCRE compiled with UTF-8 support, which is the default.
- No Composer, no extensions beyond core. `ext-intl` and `ext-mbstring` are not
  used; the tool ships its own pure-PHP UTF-8 encode and decode.

## Responsible use

Invisible carriers have legitimate uses: watermarking your own documents,
tracing leaks of material you control, and producing test fixtures for detection
tools. They also have obvious ways to be misused, so two limits are worth
stating plainly.

This tool does not defeat AI content labelling, and is not a way to do so. Under
the EU AI Act a disclosure that content is AI generated has to be **visible to
the reader**, not concealed in characters they cannot see. Hiding a mark in
invisible carriers does not satisfy that obligation. If a text needs to be
labelled as AI generated, the label belongs in the visible text.

Embedding a tracking identifier into text you then send to other people can
carry privacy and legal implications depending on where you and they are. That
is your responsibility to assess, not the tool's.

## Related

If you need the other direction, detecting and stripping these carriers rather
than adding them, pair this with a sanitizer that decodes the same three
encodings. Link your sanitizer repository here.

## The other direction

This project only adds carriers. If you need to *remove* them, its companion
does the inverse: [LLM-Sanitizer](https://github.com/MrRolid/LLM-Sanitizer)
detects and strips the same three encodings this tool embeds, decoding any
hidden payload before it deletes it.


## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 Rolid spol. s r.o.
