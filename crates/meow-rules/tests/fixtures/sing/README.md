# sing-box interoperability fixtures

The published MetaCubeX files below are unchanged and licensed GPL-3.0, whose
license is included at `../upstream/LICENSE-MetaCubeX-GPL-3.0`.

- `0x0.json`, `0x0.srs`, `private.json`, `private.srs`: MetaCubeX/meta-rules-dat
  commit `47fe33701f64a9a4e02b9c3a4237e0223b763196`, paths
  `geo/geosite/0x0.{json,srs}` and `geo/geoip/private.{json,srs}`. Published SRS
  version 2; corresponding JSON source is included beside the binaries.
- `geosite-lite.db`: MetaCubeX/meta-rules-dat release commit
  `d7fba95fbfc9eb82ec33b1762b3d7e11833eacd9`, `geosite-lite.db` (283731 bytes).
  This is the actual legacy sing-box multi-category database, with 24 categories.

Generated upstream encoder outputs use synthetic reserved `.example` input.
These were produced in temporary Go modules outside the repository:

- `headless.json` is the complete input to sing-box's own
  `common/srs.Write(writer, options, version)` for each version 1 through 5,
  yielding `headless-v{1,2,3,4,5}.srs`. Upstream commit
  `dfb80349bf5779ec0a3f834c9ec2794345bff8f0`, module
  `v1.14.4-0.20261013140250-dfb80349bf57`. Tests assert the same positive and
  negative domain/IP/source-IP and nested logical AND/OR/invert results for all
  five files and the JSON input. They do not roundtrip through a meow encoder.
- `legacy-semantics.db`: upstream sing-box v1.11.0 `common/geosite.Write`, with
  category `test` containing typed items `(0, exact.example)`,
  `(1, both.example)`, `(1, .sub.example)`, `(2, needle)`, `(3, ^regex\.)`,
  plus category `ignored` containing `(0, ignored.example)`. This verifies all
  four item types, allowlisting, exact and suffix-only semantics.

Primary sources checked on 2026-10-19: sing-box testing `constant/rule.go`
(current SRS versions 1–5), `common/srs/{binary,ip_set}.go`,
`option/rule_set.go`, `route/rule/{rule_headless,rule_abstract}.go`; sing's
`common/domain/{matcher,set}.go`; sing-box v1.11.0
`common/geosite/{reader,writer,rule}.go`.

SHA-256:

```text
d108b71da610bd26b1261c4e4701f48b6bf61f31f32f8fb460252bea6e95159a  0x0.json
95552d58947e89df7ca2cae9464887e3667a7fb071e52afc2a7a62b32c362808  0x0.srs
7798db29fc6ef281d9fc192e7ad305845a7122ae46fb7db0f6b48d720f004ff5  private.json
aa5331117805821ed6c4bcf30d4e844e73af4a1b3c8ad9bc8e67b1c26e3a75a7  private.srs
6ea74d55e9664571511751f7dccbe19e043cdd552965beb95e495a5fa4cdb0c8  geosite-lite.db
5bc701c402272f82493fb0071e1861ed27e85f3061ee31ec0e45d1f20cf64b0f  headless-v1.srs
b981722809d9eb4dca30a84f70bf51274ffb6facc126261221199c36288abbce  headless-v2.srs
bd43c2f8f3c702932182f4233d8e24d96327b015abf364568b943d6fa7dccb2e  headless-v3.srs
d7b80ae480e6ed7b536ebef1b3208392ba7fb1cad243c430e388d9ffa15b87b8  headless-v4.srs
c760b9912cf92901dfa682de11939a2666eb1cefbd5356458be8898548d8e9bf  headless-v5.srs
e9add6ce015c15e092b67b256b3269b040f97849bc292789e4168c5d331cf3dd  headless.json
cc12f7057adb2811040f322503f0e251432d93be1d6fcbd41e64c731234c5823  legacy-semantics.db
```
