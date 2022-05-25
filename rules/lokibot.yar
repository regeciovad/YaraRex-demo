import "cuckoo"

rule Lokibot {
  condition:
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\www-main-desktop-player-skeleton-webp-vflgR7NUp\.css/) or
    cuckoo.sync.mutex(/(^|\\)14E11E0BF783BCDB0BD10C30/) or
    cuckoo.sync.mutex(/(^|\\)qazwsxedc/) or
    cuckoo.sync.mutex(/(^|\\)Adobe_uza/) or
    cuckoo.sync.mutex(/(^|\\)XTREMEUPDATE/) or
    cuckoo.sync.mutex(/(^|\\)itBGuTAr(EXIT)?/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\K-Meleon/) or
    cuckoo.registry.key_access(/(^|\\)Software\\(NCH Software\\Fling\\|WinChips\\User)Accounts/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\8pecxstudios\\Cyberfox(86)?/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\MICROSOFT\\Cryptography\\MachineGuid/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\Wow6432Node\\Microsoft\\Windows( Script Host\\Settings|\\CurrentVersion\\Internet Settings\\WinHttp\\Tracing)\\Enabled/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Program Files \(x86\)\\Automize1[0-9]\\data\\settings\\ftpProfiles-j\.jsd/) >= 5 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\kgfmqxac\.fhk\.(EN|ENU|exe)/) >= 3 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Foxmail\*/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\Opera( Mail\\Opera Mail|\\Opera7\\profile)\\wand\.dat/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\made\.rtf/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\(Program Files\\Google\\Chrome\\Application\\85\.0\.4183\.83\\Secur|Windows\\winsxs\\x86_microsoft\.windows\.common-controls_6595b64144ccf1df_6\.0\.7601\.18837_none_41e855142bd5705d\\comctl)32\.dll/)
}
