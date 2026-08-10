# TODO

## Dedicated Raspberry Pi image via patch_image.sh

`patch_image.sh` already patches a stock Raspberry Pi OS image with the
service files and boot config, but it does not install the runtime packages
from `install_packages.sh` (avrdude, gcc-avr, build-essential, avr-libc,
libbcm2835-dev, git, vim) into that image — today it only works if the base
image already has them.

Idea: extend `patch_image.sh` to `chroot` into the mounted root partition and
run `apt-get install` for those packages. They're all stock
Debian/Raspberry Pi OS packages, so no custom package repository is needed —
the chroot's own `apt` config points at the same repos already in the base
image's `sources.list`.

Caveat: if the image is built on an x86_64 machine, `chroot`-ing into the
ARM rootfs and running `apt`/`dpkg` (ARM binaries) requires
`qemu-user-static` + `binfmt_misc` registered on the build host first, so
the build host can execute ARM code inside the chroot. That's the same
mechanism `pi-gen` (the official Raspberry Pi OS build tool) already wraps.
So this is a real added build-time dependency, not a one-line change, even
though it's still lighter than adopting `pi-gen` wholesale for a project
this size.
