import "cuckoo"

rule Adload {
  condition:
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\SECUR32\.DLL/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\sowSWeaDvoNT/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Windows\\rch4UeC21o3E66/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\[0-9A-F]{20}\.(EN|ENU|en|exe)/) >= 4 or
    cuckoo.registry.key_access(/(^|\\)Software\\Downloader\\installedcampaigns/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Wow6432Node\\Microsoft\\NET Framework Setup\\NDP\\v3\.0\\Se(rvicing\\Windows Workflow|tup\\Windows (Communication|Presentation|Workflow)) Foundation/) >=4
}
