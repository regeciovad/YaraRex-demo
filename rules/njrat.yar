import "cuckoo"

rule njRAT {
  condition:
    cuckoo.sync.mutex(/(^|\\)5e7dec108d220a610d855491b0d9c071/) or
    cuckoo.sync.mutex(/(^|\\)5cd8f17f4086744065eb0992a09e05a2/) or
    cuckoo.sync.mutex(/(^|\\)6yRz3wfPERSIST/) or
    cuckoo.sync.mutex(/(^|\\)VLC ipc 3\.0\.11/) or
    cuckoo.sync.mutex(/(^|\\)08f4dc96bbb7af09d1a37fe35c75a42f/) or
    cuckoo.sync.mutex(/(^|\\)279f6960ed84a752570aca7fb2dc1552/) or
    cuckoo.sync.mutex(/(^|\\)bfmscuhrcnwgmy/) or
    cuckoo.sync.mutex(/(^|\\)tempbbmmessenger\.exe/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\assembly\\NativeImages_v2\.0\.50727_32\\index1e1\.dat/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\assembly\\NativeImages_v2\.0\.50727_.{47,55}\.ni\.dll/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\x64btit\.txt/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\AppData\\Local\\Temp\\AppVCatalog/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\reset\\bdechangepin\.bat/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\(bcdedit\\CloudExperienceHost|ie4uinit\\UserOOBE)Broker\.(bat|exe)/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\.{14,41}dll\.DLL/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\VirtualStore/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\System32\\eventvwr\.\*/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\h21vnc\.exe/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\(IXP000\.TMP\\image|i(is|mage))res\.dll/) or
    cuckoo.registry.key_access(/(^|\\)S(OFTWARE\\Microsoft\\CTF\\Compatibility|oftware\\Microsoft\\Windows\\CurrentVersion\\App Paths)\\njRAT v0\.7d\.exe/) >= 3 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\M(ICROSOFT\\\.NET(FRAMEWORK|Framework)|icrosoft\\\.NETFRAMEWORK)\\CLRLoadLogDir/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Classes\\(ChromeHTML\\(Always|Never)|VLC\.avi\\(Always|Never))ShowExt/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)Control Panel\\DESKTOP\\SmoothScroll/) or
    cuckoo.registry.key_access(/(^|\\)Software\\Local AppWizard-Generated Applications\\PROJ\\Settings\\PreviewPages/)
}
