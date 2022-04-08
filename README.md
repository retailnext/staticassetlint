# `staticassetlint`

If this tool finds any files in the specified directories that don't have
their cryptographic digest in their filename, it will exit 1.

Currently, `staticassetlint` supports files named based on their:
* MD5
* SHA1
* SHA256

## Usage

Run `staticassetlint` as part of a build to prevent accidentally polluting
cache-forever never-revalidate asset delivery with files that are not
correctly named.

```shell
staticassetlint /workspace/foo_public /workplace/bar_public ...
```

### Skipping files

Some asset pipelines produce files that are named based on a hash of an
intermediate state that is impractical or impossible to reconstruct from the
files on disk.

You can allowlist patterns that you know are safe for use with write-once
distribution using the `--skip` flag.

Each `--skip` regular expression is anchored before compilation, meaning that
it must match the entire name of the file. (`--skip '-bar\.js'` will match
a file named `-bar.js` but not a file named `foo-bar.js`.)

Example:

```shell
staticassetlint \
    --skip '.*-[0-9a-f]{32}.(?:js|map|css)' \
    --skip 'chunk.\d{3}\.[0-9a-f]{20}\.(?:js|js\.LICENSE\.txt|map|css)' \
    /workspace/web_root/assets
```

## Contributing

Contributions considered, but be aware that this is mostly just something we
needed. It's public because there's no reason anyone else should have to waste
an afternoon (or more) building something similar, and we think the approach
is useful enough that others might benefit from adopting it.

This project is licensed under the [Apache License, Version 2.0](LICENSE).

Please include a `Signed-off-by` in all commits, per
[Developer Certificate of Origin version 1.1](DCO).
