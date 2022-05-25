# YaraRex Demo Rules

A set of Yara rules for demonstration of the YaraRex tool. The tool itself will be published soon. 

The directory `rules` contains 9 Yara rules. 

The file `cuckoo_patch_file.patch` contains a small change in Yara code. This can be applied after downloading Yara from [the official repository](https://github.com/VirusTotal/yara):

```
git apply cuckoo_patch_file.patch 
```

Dataset of CAPE reports are available here: https://drive.google.com/file/d/1Lx5e4vMN7BWZroVkxczEfcLX_p\C0nLwT/view?usp=sharing.