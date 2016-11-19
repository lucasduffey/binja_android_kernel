# Linux Installation
```
cd ~/.binaryninja/plugins
git clone https://github.com/lucasduffey/binja_android_kernel
```

# Usage
expects decompressed zImage

Factory Nexus + Pixel firmware is stored at https://developers.google.com/android/images. The firmware contains a boot.img, which contains zImage.gz + initrd.

how to get zImage
```
# prereqs
sudo apt install abootimg

$ file boot.img
boot.img: Android bootimg, kernel (0x8000), ramdisk (0x2000000), page size: 4096, cmdline (androidboot.hardware=angler androidboot.console=ttyHSL0 msm_rtb)

# extracting
abootimg -x boot.img # produces bootimg.cfg  initrd.img  zImage

$ file *
bootimg.cfg: ASCII text
initrd.img:  gzip compressed data, from Unix
zImage:      gzip compressed data, max compression, from Unix

# extract initrd.img (compressed rootfs)
cp initrd.img initrd.gz # file indicated it was gziped file
gunzip initrd.gz # can't mount resulting initrd
cpio -idv < initrd # WARNING will dump all files in same directory

# extract zImage
cp zImage zImage.gz # file indicated it was gziped file
gunzip zImage.gz

$ file *
bootimg.cfg: ASCII text
initrd:      ASCII cpio archive (SVR4 with no CRC)
zImage:      data
```
