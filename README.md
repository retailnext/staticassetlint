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

    staticassetlint /workspace/foo_public /workplace/bar_public ...

## Contributing

Contributions considered, but be aware that this is mostly just something we
needed. It's public because there's no reason anyone else should have to waste
an afternoon (or more) building something similar, and we think the approach
is good enough that others might benefit from adopting.

This project is licensed under the [Apache License, Version 2.0](LICENSE).

Please include a `Signed-off-by` in all commits, per
[Developer Certificate of Origin version 1.1](DCO).
