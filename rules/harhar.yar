import "cuckoo"

rule HarHar
{
  condition:
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\config\.json/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\config-nkxmr\.json/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\.json/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\.{5,25}\\desktop\.ini/) >= 12
}
