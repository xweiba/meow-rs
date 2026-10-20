# Upstream interoperability fixtures

These are published data and small outputs of the actual upstream encoders,
used offline. Tests do not generate their own MRS/DAT expectations. No private
database or subscription is included.

| File | Source revision and path | SHA-256 |
| --- | --- | --- |
| github.mrs | MetaCubeX/meta-rules-dat, `7c782352439ce9ccaba53519ec816f82f52b6285`, `geo/geosite/github.mrs` | `1ff37cbbd49e7962ac781014c400e2b292d09148c96791536b92c184837edf60` |
| private.mrs | Same revision, `geo/geoip/private.mrs` | `076ea1da10b442f01c6fb3b86a66411727a15df69d70e8d600a8a458b07a8bb0` |
| domain-semantics.mrs | Upstream mihomo DomainSetBuilder/WriteBin, `88dcbf7f1614a67c3b36b848ee3592dfa92ada36` (`v1.19.32`), synthetic reserved `.example` domains | `b9b2a3517cc9b94d39a16ad5ae4be28de1654f4ac33d069493050a15b4abb9c0` |
| private.dat | Loyalsoldier/geoip, `bf01519a9e21f366266bd48c6afae430ec8febfe`, `private.dat` | `ac5f6df7cf67c2f19e42f7bacdecdff7660671eab164af91633399517af00b73` |
| GeoIP2-Country-Test.mmdb | maxmind/MaxMind-DB, `0ee49278e35fd7bdf341ac236edbba20de1aceb9`, `test-data/GeoIP2-Country-Test.mmdb` | `ff5a273c91d332bcfb4d808cc128c4f98cb59bb55f75931b64ff69022ddfa1bc` |
| GeoLite2-ASN-Test.mmdb | Same MaxMind revision, `test-data/GeoLite2-ASN-Test.mmdb` | `5f2da5602a6947dae10486fe337d6112d2e37eaa2bc8d32e1fdeeeae645a3e4a` |

MetaCubeX data is GPL-3.0; the original corresponding `github.list` and
`private.list` are included beside the binaries, with the license text.
Loyalsoldier data is CC-BY-SA-4.0; the unchanged private-network DAT and its
license are included with attribution here. MaxMind's test databases are
Apache-2.0; the license is included. These licenses apply only to their
respective fixture files, not to the Rust implementation.

The synthetic fixture input is six reserved test patterns: `.suffix.example`,
`+.both.example`, `exact.example`, `*.wild.example`, `中文.example`,
`+.测试.example`. It verifies the upstream suffix marker and rune reversal,
including negative root/subdomain matches that an ASCII roundtrip misses.
It was produced outside the repository using upstream DomainSetBuilder.Insert,
Build().WriteBin and a zstd writer wrapping `MRS\x01`, domain behavior 0,
int64 big-endian original input count 6 and int64 big-endian reserved length 0.
Temporary Go modules/generators are not shipped in this repository.

Primary format references checked on 2026-10-19:

- MetaCubeX/mihomo `Meta`: `rules/provider/mrs_reader.go`,
  `component/trie/domain_set_bin.go`, `component/cidr/ipcidr_set_bin.go`.
- v2fly/v2ray-core `master`: `app/router/routercommon/common.proto`.
- SagerNet/sing-box `v1.11.0`: `common/geoip/reader.go`,
  `common/geosite/reader.go`, `common/srs/binary.go`.

MRS is one domain or IP rule set, not a multi-category GeoSite database.
The older local `MRS!` container remains a legacy compatibility path only.
sing-box GeoIP DB is an MMDB with database type `sing-geoip` and country-string
records; it is supported by the country index. Additional supported sing-box
GeoSite DB, SRS and JSON fixtures are documented in `../sing/README.md`.
