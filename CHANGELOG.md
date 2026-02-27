# Changelog

## [0.3.0](https://github.com/enboxorg/meshd/compare/v0.2.0...v0.3.0) (2026-02-27)


### Features

* ACL policy records for packet filter enforcement ([#62](https://github.com/enboxorg/meshd/issues/62)) ([a9e4571](https://github.com/enboxorg/meshd/commit/a9e4571424307006f4f8a61e2663349d152f676c)), closes [#31](https://github.com/enboxorg/meshd/issues/31)
* add daemon control socket for meshd up/down/status ([6398d06](https://github.com/enboxorg/meshd/commit/6398d0621b5658a57fd04db95e3b132e60735149)), closes [#30](https://github.com/enboxorg/meshd/issues/30)
* add didjwk.Create() for node identity generation ([80a6253](https://github.com/enboxorg/meshd/commit/80a6253a294307a52b6929b47104ec85796271a8))
* add didjwk.Create() for node identity generation ([a64150a](https://github.com/enboxorg/meshd/commit/a64150ab3256b00eb7dcd1bcd93dbbe16f12b50a)), closes [#44](https://github.com/enboxorg/meshd/issues/44)
* daemon control socket for meshd up/down/status ([cdcc50e](https://github.com/enboxorg/meshd/commit/cdcc50e90b392cf9d1c2b2a17c8d2c7260a17cd7))
* implement peer add CLI command ([ba1080c](https://github.com/enboxorg/meshd/commit/ba1080cda203047353b65e11fd0a87ba393e246d))
* implement peer add CLI command ([a12b3e0](https://github.com/enboxorg/meshd/commit/a12b3e0a400223fb27367a111d35e460fa76fcf6)), closes [#28](https://github.com/enboxorg/meshd/issues/28)
* protocol redesign with member layer, dual node paths, and recipient-based auth ([#82](https://github.com/enboxorg/meshd/issues/82)) ([#84](https://github.com/enboxorg/meshd/issues/84)) ([640bccc](https://github.com/enboxorg/meshd/commit/640bccc96f143e5d6911880a34160d9c23352578))
* protocol-level filtering in ACL rules ([#64](https://github.com/enboxorg/meshd/issues/64)) ([#91](https://github.com/enboxorg/meshd/issues/91)) ([8b05ac6](https://github.com/enboxorg/meshd/commit/8b05ac6c636dd6c8d3172bc80c96e46959465825))
* real TUN device support for kernel-level mesh networking ([21838e6](https://github.com/enboxorg/meshd/commit/21838e6ac156fe8ec3e9c51648944c02ed1d3103))
* real TUN device support for kernel-level mesh networking ([f8d3853](https://github.com/enboxorg/meshd/commit/f8d38532ae46e01900f276d78203d4fcc3357508)), closes [#25](https://github.com/enboxorg/meshd/issues/25)
* smart meshd up with guided setup and one-command workflows ([d439a4e](https://github.com/enboxorg/meshd/commit/d439a4e378000a7b0dc77fa8d7346e954d62b064))
* smart meshd up with guided setup and one-command workflows ([cc710d9](https://github.com/enboxorg/meshd/commit/cc710d95ad37e787a0dabb16419f8f2b26b9a9b9)), closes [#29](https://github.com/enboxorg/meshd/issues/29)
* wire DWN subscriptions to engine for real-time peer updates ([9106bb9](https://github.com/enboxorg/meshd/commit/9106bb9864dc0115815b57ba28c94a9c43564f20))
* wire DWN subscriptions to engine for real-time peer updates ([3296d53](https://github.com/enboxorg/meshd/commit/3296d539881a70847c0556f5bae95327f111230c)), closes [#29](https://github.com/enboxorg/meshd/issues/29)


### Bug Fixes

* audit bug fixes ([#67](https://github.com/enboxorg/meshd/issues/67)-[#75](https://github.com/enboxorg/meshd/issues/75)) ([#79](https://github.com/enboxorg/meshd/issues/79)) ([317ae05](https://github.com/enboxorg/meshd/commit/317ae05da1b4d9d6778ce18908e553448617fd8a))
* detect offline peers using endpoint record timestamps ([b8328a0](https://github.com/enboxorg/meshd/commit/b8328a018d6a2178d074daed86ca1ab3987c1d01))
* detect offline peers using endpoint record timestamps ([72649ce](https://github.com/enboxorg/meshd/commit/72649ce49c4bc4cf0a157636e2ce2dc5a85ee7b3)), closes [#32](https://github.com/enboxorg/meshd/issues/32)
* persist context key locally and remove dead node re-encryption ([#90](https://github.com/enboxorg/meshd/issues/90)) ([acd8fc7](https://github.com/enboxorg/meshd/commit/acd8fc7c695bc39ec27464bcee877681859711b3))
* use Protocol Context encryption for all records so peers can decrypt ([#87](https://github.com/enboxorg/meshd/issues/87), [#88](https://github.com/enboxorg/meshd/issues/88)) ([#89](https://github.com/enboxorg/meshd/issues/89)) ([45e5245](https://github.com/enboxorg/meshd/commit/45e5245fb5aa76a2ccc73668701dfa6c0ca06c34))
* zero sensitive crypto key material after use ([#78](https://github.com/enboxorg/meshd/issues/78)) ([#81](https://github.com/enboxorg/meshd/issues/81)) ([20f5bd0](https://github.com/enboxorg/meshd/commit/20f5bd0a96d7480dec3f39dde60b61562c9df8de))

## [0.2.0](https://github.com/enboxorg/meshd/compare/v0.1.0...v0.2.0) (2026-02-25)


### Features

* exchange disco keys via DWN endpoint and nodeInfo records ([d8c15bf](https://github.com/enboxorg/meshd/commit/d8c15bf3f261857510b388728d06368554b846c4))
* exchange disco keys via DWN endpoint and nodeInfo records ([7e048ea](https://github.com/enboxorg/meshd/commit/7e048ea794685cf543fc4450de5473e13e7a4a84))

## [0.1.0](https://github.com/enboxorg/meshd/compare/v0.0.3...v0.1.0) (2026-02-25)


### Features

* integrate enbox identity profiles (~/.enbox/) ([b6fd737](https://github.com/enboxorg/meshd/commit/b6fd73799126b832e5299eeef8abe8575131da2d))
* integrate enbox identity profiles for shared ~/.enbox/ identity management ([90c89cb](https://github.com/enboxorg/meshd/commit/90c89cb1c9c90d6af662baffb3d4d6398030d7da))

## [0.0.3](https://github.com/enboxorg/meshd/compare/v0.0.2...v0.0.3) (2026-02-25)


### Bug Fixes

* inline binary builds into release-please workflow ([4127891](https://github.com/enboxorg/meshd/commit/41278914a23cc969914d90e57fc305fb9c020dd1))
* inline binary builds into release-please workflow ([7450b8b](https://github.com/enboxorg/meshd/commit/7450b8b886ca352eeac1c4e172d1c0117cdf2659))

## [0.0.2](https://github.com/enboxorg/dwn-mesh/compare/v0.0.1...v0.0.2) (2026-02-25)


### Bug Fixes

* resolve unbound variable in install script cleanup trap ([9bc5b04](https://github.com/enboxorg/dwn-mesh/commit/9bc5b047c3d6f5c3c199e42ed4e35896c28671a4))
* resolve unbound variable in install script cleanup trap ([dbd309d](https://github.com/enboxorg/dwn-mesh/commit/dbd309d26aa0a6b729aaaf8eec76753b90611afc))
