# DeepScan CoreLogic — PhotoRec Porting Status

DeepScan's `CoreLogic` is a C++ port of the core file-carving engine of
**PhotoRec** (part of CGSecurity's TestDisk suite, written in C). The port
targets Windows/MSVC first (see `include/config.h`, `hdwin32.cpp`,
`win32.cpp`) while keeping the original POSIX code paths behind the same
`HAVE_*` feature macros, so a Linux build remains reachable.

The repository also contains `file_jpg_standalone.c`, a self-contained,
dependency-free JPEG recovery debugger based on PhotoRec's `file_jpg.c`
logic — useful for exercising the JPEG carving logic outside the engine.

## 1. Architecture: how the C original maps to the C++ port

The port is not a mechanical transliteration — the intrusive `td_list`
machinery and function-pointer tables of the C original were replaced with
idiomatic C++ while keeping the engine logic identical. The mapping
(documented in `file_gen.h`):

| PhotoRec (C) | CoreLogic (C++) |
|---|---|
| `file_hint_t` + `register_header_check` | abstract `class Carver` (`register_signatures`, `header_check`) |
| `file_stat_t` per-format counters | `CarverStats` member inside each `Carver` |
| `file_check_plist` / `file_check_list` globals + `index_header_check` | `class SignatureIndex` (add → build → identify) |
| `array_file_enable` (`file_list.h`) | `CarverRegistry` singleton; each carver `.cpp` self-registers a static instance |
| `file_recovery_t` + `reset_file_recovery` + `file_search_footer` / `file_allow_nl` / `file_rename` | `class FileRecovery` (owns its `FILE*`; closes on reset/destroy) |
| `offset_skipped_header`, `gpls_nbr`, `header_ignored*`, `get_prev_location` | `CarveSession` singleton |
| `td_list` circular search space (`alloc_data_t` chain) | `SearchSpace` = `std::list<alloc_data_t>`; the old sentinel head maps to `end()` |
| mutable function-pointer slots (`data_check`, `file_check`, `file_rename`) | `std::function` strategy slots (carvers still swap them mid-carve) |
| hard-coded `file_hint_tar` special case in scan loops | virtual `Carver::skip_header_scan` (only tar overrides) |
| `my_fseek`, `file_rsearch`, date parsers | `FileGenUtil` static helpers (`int64_t` replaces 32-bit `off_t` on MSVC) |

Notable engine-behavior-preserving details: `prev_of`/`next_of` reproduce
the circular-list wrap-around, `FileRecovery::operator=` reproduces the
`file_recovery_cpy` memcpy semantics (empty fragment list, borrowed
handle), and `probe_check_size()` replaces the `fr_test` memcpy trick in
`header_ignored_adv`.

## 2. What has been ported

### Engine (core carving loop)
- `phbs.c` → `phbs.cpp` — blocksize detection pass (`photorec_find_blocksize`).
- `psearchn.c` → `psearchn.cpp` — the main carving pass (`photorec_aux`),
  including back-tracking (`get_prev_location_smart`), lowmem `forget`,
  and truncate-and-move handling.
- `photorec.c` → `photorec.cpp` — search-space management
  (`init_search_space`, `del_search_space`, `update_blocksize`,
  `find_blocksize`), file finishing (`file_finish2`, `file_finish_bf`,
  `file_recovery_aborted`), filenames/dirs (`set_filename`,
  `photorec_mkdir`), stats (`update_stats`, `write_stats_log`),
  `params_reset`, `status_inc`, `init_list_part`, `new_whole_disk`.
- `file_found.c`, `pnext.h` (`get_next_sector`), `psearch.h`,
  `photorec_check_header.h` — ported.

### Platform / device layer
- `hdaccess.c`, `hdcache.c` (read cache), `hdwin32.c`, `win32.c`,
  `hpa_dco.c`, `fnctdsk.c`, `alignio.h` — ported; Windows raw-device
  access works through `win32.cpp`.
- `partnone.c` — "no partition table" arch (the only partition arch in
  this build; `is_fat()`-dependent code paths were dropped accordingly).
- `common.c`, `setdate.c`, `log.c`, `log_part.c`, `intrf.c` (subset),
  `dir.c` (subset) — ported.
- `include/config.h` — hand-written MSVC config replacing autoconf
  (`_CRT_SECURE_NO_WARNINGS`, `__attribute__` neutralization, `mkdir`
  mapping, `mode_t`, etc.).

### New code (not in upstream PhotoRec)
- `json_log.cpp/h` — structured JSON logging of session start/resume,
  disk/partition info, progress, and completion; intended as the
  machine-readable interface for a future GUI/front-end.
- `DeviceInterface.cpp` — interim console driver (`main`): enumerates
  disks, wraps them in the read cache, prompts for a disk, runs the
  blocksize pass, then runs one `photorec_aux` carving pass.

### File-format carvers (11 families, photo-recovery-focused)
| Carver | Formats |
|---|---|
| `file_jpg.cpp` | JPEG (largest carver; libjpeg-based decode validation dropped — see §3) |
| `file_tiff.cpp` + `_be`/`_le` | TIFF + raw formats riding on TIFF (pef/nef/dcr/sr2/cr2…) |
| `file_raf.cpp` | Fujifilm RAF |
| `file_rw2.cpp` | Panasonic/Leica RW2 |
| `file_mov.cpp` | mov/mp4/3gp/3g2/jp2 |
| `file_riff.cpp` | RIFF: wav, avi, cdr |
| `file_doc.cpp` | OLE compound documents (doc/xls/ppt & many OLE-based formats) |
| `file_indd.cpp` | Adobe InDesign |
| `file_tar.cpp` | tar (also exercises `skip_header_scan`) |
| `file_journal.cpp` | systemd journal |

Upstream PhotoRec ships ~300 `file_*.c` parsers; ~290 remain unported.

## 3. Deliberately dropped or stubbed (documented in-source)

- **Session save/resume** (`sessionp.c`) — not ported; checkpoint call
  sites in `psearchn.cpp` are commented placeholders.
- **Filesystem-aware carving** (`ext2p`/`fatp`/`ntfsp`/`exfatp`) —
  `PhotoRec::remove_used_space` is stubbed to return 0 (always carves the
  whole space); "free space only" mode is therefore inert.
- **FAT 4GB cap / `is_fat()` checks** — dropped (partition arch is "none").
- **ncurses UI** (`phrecn.c` interface, progress bar, `photorec_info`) —
  replaced by `std::cout` prompts + JSON logging.
- **libjpeg decode validation** in `file_jpg.cpp` — dropped
  (`HAVE_LIBJPEG` undefined); JPEG validation is structural only.
- **`fopen_with_retry`** (Cygwin/MinGW antivirus workaround) and the FAT
  directory listing in `photorec_check_header.h` — dropped.
- **EWF image support** (`libewf`) — present behind `HAVE_LIBEWF` but not
  enabled in the MSVC config.

## 4. Known gaps / issues in the current driver

1. **`params.partition` is never initialized.**
   `photorec_disk_selection` calls `PhotoRec::init_search_space(...,
   params->partition)` without ever assigning a partition.
   `init_list_part` / `new_whole_disk` exist but are not called from
   `DeviceInterface.cpp` — this must be wired before the engine can run
   safely.
2. **The outer recovery loop from `phrecn.c` is missing.** Upstream
   `photorec()` drives multiple passes through the status state machine
   (`STATUS_FIND_OFFSET → STATUS_EXT2_ON/OFF → …_BF → …_SAVE_EVERYTHING`),
   calling `status_inc`, `update_stats`, `write_stats_log`, and
   `photorec_mkdir` between passes. All those helpers are ported, but
   nothing calls them: `main` runs the blocksize pass plus a single
   `photorec_aux` and exits.
3. **Brute-force pass (`phbf.c`) not ported** — `file_finish_bf` exists,
   but the `STATUS_*_BF` passes that use it have no driver.
4. **Hard-coded output dir** — `params->recup_dir = "H:\\out"` in
   `DeviceInterface.cpp`; no `photorec_mkdir` call, no CLI option.
5. **`need_to_stop`** lives temporarily in `phbs.cpp`; no signal
   handler/UI sets it yet.
6. Minor: `/* FIXME REMOVE ME */` debug remnant in `file_jpg.cpp:905`;
   TIFF-LE has an upstream-inherited `TODO` at `file_tiff_le.cpp:459`.
7. **Licensing**: PhotoRec is GPLv2+, so the port is a derivative work and
   is GPLv2+ as well. This repo now carries `COPYING` (the GPLv2 text) and
   `LICENSE_HEADER_TEMPLATE.txt`; the template header still needs to be
   applied to each file in the CoreLogic source tree (which lives outside
   this repo).

## 5. What to do next (suggested order)

1. **Wire the outer loop** — port `phrecn.c`'s `photorec()` skeleton:
   create the recovery directory (`photorec_mkdir`), run the status state
   machine with `status_inc`, call `update_stats`/`write_stats_log`, and
   loop `photorec_aux` per pass. This turns the current one-shot demo into
   a real recovery run.
2. **Fix the driver** — initialize `params.partition` via
   `init_list_part`/`new_whole_disk` (or a partition prompt), make
   `recup_dir` a user input/CLI arg, propagate `pstatus_t` results, and
   hook Ctrl-C to `need_to_stop`.
3. **Grow carver coverage** by target use case — for a photo/media
   recovery product the next candidates are: png, gif, bmp, cr3 (canon),
   heic (rides on `file_mov`'s bases), arw/sr2, orf, dng, mp3, zip/docx,
   pdf, mkv. Each is an independent `Carver` subclass, so these are
   parallelizable, low-risk tasks.
4. **Session save/resume** (`sessionp.c`) — long scans on big disks need
   checkpointing; the call sites are already marked in `psearchn.cpp`.
5. **Brute-force mode** (`phbf.c`) if paranoid/BF recovery is wanted.
6. **Filesystem awareness** — port `ext2p`/`fatp`/`ntfsp`/`exfatp` to make
   `remove_used_space` and "free space only" carving real.
7. **Optional JPEG decode validation** — reintroduce libjpeg(-turbo)
   behind `HAVE_LIBJPEG` to cut false positives on fragmented JPEGs.
8. **Build & test infrastructure** — a CMake build (MSVC + Linux), plus
   regression tests carving known disk images and diffing results against
   upstream `photorec` output; the standalone JPEG tool can seed a
   unit-test harness for `file_jpg`.
9. **GPL compliance** — `COPYING` and a header template are now in this
   repo; apply the header to every CoreLogic source file, and decide the
   product's licensing strategy early (fully GPL product vs. GPL engine as
   a separate process behind a proprietary front-end vs. clean-room
   replacement).
