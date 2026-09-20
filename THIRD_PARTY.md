# Third-party code and routing data

lazyclash's own code uses the root MIT license. Go dependencies retain their
upstream licenses; versions and integrity hashes are recorded in go.mod/go.sum.
The local QR encoder is [skip2/go-qrcode](https://github.com/skip2/go-qrcode) (MIT).

The embedded routing snapshot comes from the immutable clash-rules artifact
`rules-27ae948beb8e304190344c28bf731fe3d1c7fbeb36e7485eb18975fcbdcb2e34`,
commit `4e0867be9ce85db758d353c0b8301ca8e789193a`.

- Handwritten category rules retain their upstream MIT license.
- Mirrored MetaCubeX geographic/domain data retains its upstream GPLv3 license
  and original notices. It is not relabeled as lazyclash's MIT code.
- Original LICENSE, THIRD_PARTY, vendor LICENSE/README, upstream lock, manifest
  and provenance remain in `internal/managedcore/assets/rules/`; setup copies
  applicable notices into the managed rules provenance directory.

The [source repository](https://github.com/daviddwlee84/clash-rules),
[immutable artifact](https://github.com/daviddwlee84/clash-rules/tree/rules-27ae948beb8e304190344c28bf731fe3d1c7fbeb36e7485eb18975fcbdcb2e34)
and retained lock identify original revisions, source URLs and file hashes.
See [references](docs/references.md) for implementation contracts and design
boundaries. Data classification does not imply an upstream endorsement of the
route policies selected by lazyclash or a user.
