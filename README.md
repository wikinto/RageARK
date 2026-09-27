# RageARK

RageARK is a plugin for KDE's [Ark](https://apps.kde.org/ark/) archive manager that opens
Grand Theft Auto V **RPF7** archives (`update.rpf`, `common.rpf`, `x64*.rpf`, DLC `dlc.rpf`, …).
It brings CodeWalker's *RPF Explorer* edit mode to Ark and Dolphin on Linux:

- **Browse** archives, including nested RPFs (shown as folders, like CodeWalker)
- **Extract** files: NG/AES decryption and decompression are handled transparently. Resources
  (`.ydr`, `.ytd`, …) are extracted with their RSC7 header, so they can be re-imported.
- **Audio:** `.awc` sound banks appear as folders with one `.wav` per stream (PCM/ADPCM, identical
  to CodeWalker's export). MP3 streams (codec 7) are extracted as `.mp3`.
- **Edit in place:** add, replace, delete, rename, move and copy files, also inside nested archives.
  Every table of contents is re-encrypted with the game's own NG encryption, so edited archives
  do not need an ASI loader, OpenIV or RageOpenV.
- **Safe editing:** before the first change, a one-time backup `<archive>.rpf.rageark-bak` is
  created. On btrfs/XFS it is an instant reflink copy.

Supported games: GTA V Legacy and Enhanced (PC).

RageARK is built out of tree against the Ark already installed on your system. Ark itself is never
rebuilt.

> **Status.** Reading, extraction and audio decoding are verified byte for byte against CodeWalker
> on real game archives. Editing is verified with CodeWalker and by re-encrypting Rockstar's own
> tables of contents. Loading edited archives in the game has not been tested yet. GTA V Enhanced
> caches every archive's table of contents in `rpf.cache`, so it may not accept edited archives
> until RageARK can update that cache (planned). Always keep the `.rageark-bak` backups.

## Game keys

RageARK ships **no Rockstar keys or game data**. Like CodeWalker, it contains only SHA-1 hashes and
derives the keys at runtime from your own game executable. It needs two things:

1. **`GTA5.exe` or `GTA5_Enhanced.exe`** from your installation. The first time you open an
   encrypted archive, Ark asks you to select it. The derived keys are cached in
   `~/.cache/rageark/keys.dat`, so this happens only once per machine. Alternatives: set the
   environment variable `RAGEARK_GTA_EXE`, or add the path to `~/.config/ragearkrc`:
   ```ini
   [Keys]
   gta_exe=/path/to/Grand Theft Auto V/GTA5_Enhanced.exe
   ```
2. **CodeWalker's `magic.dat`** (`CodeWalker.Core/Resources/magic.dat` in the
   [CodeWalker](https://github.com/dexyfex/CodeWalker) repository). It holds the NG key tables,
   encrypted with the key from your exe, and is useless without it. RageARK does not ship it. Pass
   it to CMake with `-DRAGEARK_MAGIC_DAT=…` to install it, or copy it to
   `~/.local/share/rageark/magic.dat`, or point `RAGEARK_MAGIC_DAT` at it.

The first edit of an encrypted archive generates the NG *encryption* tables once. This takes about
15 s on a modern CPU; the result is cached as well (about 44 MB).

## Required packages

The plugin must be compiled against the Ark version that is installed (see
[Ark version](#ark-version)).

### Debian 13 (trixie) / Ubuntu 25.04+

```sh
sudo apt install build-essential cmake extra-cmake-modules git \
    qt6-base-dev libkf6coreaddons-dev libkf6i18n-dev libkf6config-dev libkf6filemetadata-dev \
    zlib1g-dev libssl-dev shared-mime-info ark
```

### Arch Linux

```sh
sudo pacman -S --needed base-devel cmake extra-cmake-modules git \
    qt6-base kcoreaddons ki18n kconfig kfilemetadata \
    zlib openssl shared-mime-info ark
```

The Flatpak and Snap versions of Ark cannot load plugins from the host system. Use the
distribution's `ark` package.

## Build

```sh
git clone https://github.com/wikinto/RageARK.git
cd RageARK
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
      -DRAGEARK_MAGIC_DAT=/path/to/CodeWalker/CodeWalker.Core/Resources/magic.dat
cmake --build build -j"$(nproc)"
```

`-DRAGEARK_MAGIC_DAT` is optional (see [Game keys](#game-keys)).

## Installation

The steps are the same on Debian and Arch:

```sh
sudo cmake --install build
sudo update-mime-database /usr/share/mime
```

This installs:

| File | Debian | Arch |
|---|---|---|
| Ark plugin | `/usr/lib/x86_64-linux-gnu/qt6/plugins/kerfuffle/kerfuffle_rageark.so` | `/usr/lib/qt6/plugins/kerfuffle/kerfuffle_rageark.so` |
| MIME type `application/x-rockstar-rpf` | `/usr/share/mime/packages/x-rockstar-rpf.xml` | same |
| `magic.dat` (if given) | `/usr/share/rageark/magic.dat` | same |

Restart Ark. Then check that:

- `xdg-mime query filetype some.rpf` prints `application/x-rockstar-rpf`
- *Settings → Configure Ark → Plugins* lists **RageARK RPF plugin**
- Dolphin offers *Open with Ark* for `.rpf` files

To try the plugin without installing it:

```sh
mkdir -p ~/.local/share/mime/packages
cp mime/x-rockstar-rpf.xml ~/.local/share/mime/packages/
update-mime-database ~/.local/share/mime
QT_PLUGIN_PATH="$PWD/build/lib" ark some.rpf
```

### Uninstall

```sh
sudo xargs rm -v < build/install_manifest.txt
sudo update-mime-database /usr/share/mime
```

## Ark version

Ark does not install its development headers, so `3rdparty/kerfuffle/` contains a copy of the few
headers the plugin needs, taken unmodified from **Ark 25.04.3** (`libkerfuffle.so.25`, Debian 13).
The plugin links against the installed `libkerfuffle.so.<N>` (versions 25–27 are searched).

If your distribution ships a different Ark release, as Arch usually does, replace the headers with
the ones from the matching release before building. Otherwise the plugin may crash or fail to load,
because the layout of classes such as `Kerfuffle::Query` changes between releases.

```sh
ark --version                                   # e.g. ark 25.08.1
curl -LO https://download.kde.org/stable/release-service/25.08.1/src/ark-25.08.1.tar.xz
tar xf ark-25.08.1.tar.xz
for h in archive_kerfuffle.h archiveentry.h archiveinterface.h metadatabackup.h options.h queries.h; do
    cp ark-25.08.1/kerfuffle/$h 3rdparty/kerfuffle/
done
```

(`3rdparty/kerfuffle/kerfuffle_export.h` is a small replacement for a file Ark generates at build
time; keep it.) Rebuild and reinstall after every Ark major upgrade.

## Configuration

`~/.config/ragearkrc`:

```ini
[Keys]
gta_exe=/path/to/GTA5_Enhanced.exe   ; written by the first-run dialog

[Awc]
decode=true      ; false: show .awc files as raw files instead of folders of .wav/.mp3

[Backup]
mode=on          ; on | reflink-only (back up only when a COW copy is possible) | off
```

If an edit is interrupted (crash, power loss), `<archive>.rpf.rageark-journal` is left behind and
Ark shows a warning when the archive is opened. Restore the `.rageark-bak` file in that case.

## Documentation

- [`docs/ANALYSIS.md`](docs/ANALYSIS.md): design, RPF7 format and crypto, write path and safety
  model, milestones
- [`docs/TESTING.md`](docs/TESTING.md): test results and the manual in-game test procedure

## Credits and legal

The RPF7, RSC7 and AWC format knowledge and the GTA V key derivation come from
[CodeWalker](https://github.com/dexyfex/CodeWalker) by dexyfex; the NG cipher follows GTACrypto /
GTAKeys by Neodymium. The headers in `3rdparty/kerfuffle` are from KDE Ark (BSD-2-Clause).

RageARK is not affiliated with Rockstar Games or Take-Two Interactive. You need your own copy of
GTA V. Modifying game files may break your installation or get you banned from GTA Online: do not
use modified archives online.
