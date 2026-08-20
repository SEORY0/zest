# Zest playbooks

Longer walkthroughs for tasks that take more than one command. Each one states what to look at,
not just what to type.

## Unpick a nested payload

Encoded data is often wrapped more than once: base64 around gzip around JSON is the canonical
shape for a compressed API response or a serialised session.

```bash
zest -i "$BLOB" magic:depth=3
```

Read the top result's chain, then run it explicitly so the steps are visible and repeatable:

```bash
zest -i "$BLOB" from-base64 gunzip json-format
```

If `magic` returns nothing, do not conclude that the input is plaintext or encrypted. Its search
is intentionally bounded. Test the representation suggested by the challenge syntax explicitly:

```bash
zest -i "$BLOB" from-decimal
zest -i "$BLOB" from-charcode:base=Hexadecimal
zest -i "$BLOB" from-binary
zest -i "$BLOB" from-morse
zest -i "$BLOB" rot:amount=13
zest -i "$BLOB" rot47
```

Use `zest op <id>` first when the input shape or argument is uncertain. If those fail, measure
entropy as evidence for the next hypothesis:

```bash
zest -i "$BLOB" entropy
```

Above 7.5 is consistent with encryption, compression or random data; it does not distinguish
between them and does not prove that a key is required.

## Work out how a value was derived

You have a plaintext and a token, and want to know the relationship.

```bash
zest -i 'user@example.test' md5
zest -i 'user@example.test' sha1
zest -i 'user@example.test' sha2:size=SHA-256
```

If none match, the value is probably salted or keyed. Check the shape first:

```bash
zest --input-env SESSION_TOKEN analyse-hash
```

Then try the common keyed constructions:

```bash
zest -i 'user@example.test' hmac:key=env:HMAC_SECRET,algorithm=SHA-256
```

## Audit a JWT properly

Decoding is not verifying. Do both, in this order.

```bash
zest --input-env SESSION_TOKEN jwt-decode
```

Check three things in the output:

1. **`alg`** — `none` means a verifier honouring it accepts any payload. `zest` flags this.
2. **`exp`** — the `claims as dates` block says expired or still valid.
3. **Claims that grant authority** — `role`, `scope`, `admin`, `aud`.

Then verify the signature, which is the only step that proves the token was not edited:

```bash
zest --input-env SESSION_TOKEN jwt-verify:secret=env:JWT_SECRET
```

A valid signature means the issuer produced it. It says nothing about whether the claims inside
are appropriate.

## Turn a CSV export into something queryable

```bash
zest -f export.csv csv-to-json > export.json
zest -f export.json json-path:path='[*].email' | zest unique-lines
```

To get back to a spreadsheet after filtering:

```bash
zest -f filtered.json json-to-csv -o filtered.csv
```

## Compare two files without a diff tool

```bash
zest -f a.bin sha2:size=SHA-256
zest -f b.bin sha2:size=SHA-256
```

Different digests tell you they differ. To find out where:

```bash
case_dir="$(mktemp -d)"
zest -f a.bin hexdump -o "$case_dir/a.hex"
zest -f b.bin hexdump -o "$case_dir/b.hex"
diff "$case_dir/a.hex" "$case_dir/b.hex" | head -20
```

The offset column in the first differing line is the byte offset.

## Build test data

```bash
# A key and nonce ready to paste into AES
zest random-key:keySize=256,ivLength=12

# A long buffer for an overflow test
zest -i 'A' repeat:count=5000

# A cycling pattern, so a crash offset is identifiable
zest -i 'Aa0Aa1Aa2Aa3' repeat:count=100

# Passwords with a stated entropy figure
zest generate-password:length=24,count=10,unambiguous=true
```

## Normalise timestamps from mixed sources

Logs rarely agree on a format. Everything here reports UTC.

```bash
zest -i 1700000000 unix-to-date          # epoch seconds
zest -i 1700000000000 unix-to-date       # milliseconds — detected by digit count
zest -i 133445222400000000 filetime-to-date   # Windows FILETIME
zest -i '2023-11-14T22:13:20Z' date-to-unix
```

A date string with no timezone is read as UTC, not local, so results are reproducible on any
machine.

## Check a value round-trips before relying on it

When building a pipeline for someone else, verify it is reversible:

```bash
zest -i 'the original' to-base64 from-base64
# the original
```

If the output does not match the input, one of the steps is lossy — most often a text operation
applied to binary data. Insert `to-raw` or switch to `--out-encoding hex` to see the actual bytes.
