import "cuckoo"

rule Ursnif {
  condition:
    cuckoo.sync.mutex(/(^|\\)FollowcoatYard/) or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\Run\\dbnespci/) or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\Run\\crypes/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\(Classes\\SystemFileAssociations\\\.(odt|tiff)\\Doc|Wow6432Node\\Microsoft\\WBEM\\CIMOM\\Enable)Object(Validation)?/) or
    cuckoo.registry.key_access(/(^|\\)Identities\\\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}\\Projectic/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Classes\\CLSID\\\{[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}\\InprocServer32/) or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\Run\\dmutsnap/) or
    cuckoo.registry.key_access(/(^|\\)Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\DragDelay/) or
    cuckoo.filesystem.file_access(/(^|\\)msl0/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\dxvanext\\dbnenput(\.ex_|\.exe)/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\"C:\\Users\\comp\\AppData\\Local\\Temp\\.{4,9}\.bat"/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(321|Users\\[^\\]+\\AppData\\Local\\Temp\\|p9DOBgnAuKLN3hP|rcGfANDeSxYV)\.txt/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\dxvanext/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Users\\[^\\]+\\AppData\\Local\\(Programs\\Python\\Python37-32\\(Scripts\\)?|Temp\\)|Windows\\System32\\WindowsPowerShell\\v1\.0\\)EkPIDSduoj/) >= 4
}
