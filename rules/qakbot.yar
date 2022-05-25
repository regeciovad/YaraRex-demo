import "cuckoo"

rule Qakbot
{
  condition:
    cuckoo.sync.mutex(/(^|\\)wuerixznbnmazejuxmsxtbfbpk/) or
    cuckoo.sync.mutex(/(^|\\)yssauwvxilqvnxmuepdgkmpyyxcwqn/) or
    cuckoo.sync.mutex(/(^|\\)inabvwlqmvsefa/) or
    cuckoo.sync.mutex(/(^|\\)00B7F0EB0B3678E70302a/) or
    cuckoo.sync.mutex(/(^|\\)0129EB452066165B48F7a/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Tiafuzdii(.{2,5})?/) or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Tiafuzdii\\(c)?ikkzowxr(32)?\.(dat|dll|exe)/) >= 2 or
    cuckoo.filesystem.file_access(/(^|\\)C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Jxoqwnx\\jxoqw\.dat/)
}
