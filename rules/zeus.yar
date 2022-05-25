import "cuckoo"

rule Zeus
{
  condition:
    cuckoo.sync.mutex(/(^|\\)Sandboxie_SingleInstanceMutex_Control/) or
    cuckoo.sync.mutex(/(^|\\)719B3C62C6D39623130B3D4D8471639E/) or
    cuckoo.sync.mutex(/(^|\\)C54D473E0189271FF9D1060019750AD7/) or
    cuckoo.sync.mutex(/(^|\\)25ACBEE4D1ED31A66947395E400E2A8C/) or
    cuckoo.sync.mutex(/(^|\\)E07D7AEEA0471D4FE8FDF2AEB037108A/) or
    cuckoo.sync.mutex(/(^|\\)0E0632600D5B4E4BE2E08ADDA92A68FC/) or
    cuckoo.sync.mutex(/(^|\\)27F7FFA07BD0546DF3E613F21C61F3E9/) or
    cuckoo.sync.mutex(/(^|\\)__SYSTEM__64AD0625__/) or
    cuckoo.sync.mutex(/(^|\\)__SYSTEM__91C38905__/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\(MICROSOFT\\WINDOWS NT\\CURRENTVERSION|Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion)\\DigitalProductId/) or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\System\\Panda/) or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Internet Explorer\\Privacy\\CleanCookies/) or
    cuckoo.registry.key_access(/(^|\\)Software\\WINE/) or
    cuckoo.registry.key_access(/(^|\\)software\\microsoft\\windows nt\\currentversion\\winlogon/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\.{20,41}msvcr100\.dll/) >= 4 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\088010711E3FCEEEB991\.exe/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\Ytawaxi/)

}
