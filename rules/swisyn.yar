import "cuckoo"

rule Swisyn
{
  condition:
    cuckoo.sync.mutex(/(^|\\)services\.exeM_[0-9]{3}_/) or
    cuckoo.sync.mutex(/(^|\\)svchost.{11}/) >= 4 or
    cuckoo.sync.mutex(/(^|\\)wininit\.exeM_[0-9]{3}_/) or
    cuckoo.sync.mutex(/(^|\\)winlogon\.exeM_[0-9]{3}_/) or
    cuckoo.sync.mutex(/(^|\\)spoolsv(\.exeM_10[0-9]{2}_|\.exeM_[0-9]{3}_)/) or
    cuckoo.sync.mutex(/(^|\\)taskhost\.exeM_[0-9]{4}_/) or
    cuckoo.sync.mutex(/(^|\\)audiodg(\.exeM_2752_|\.exeM_[0-9]{3}_)/) or
    cuckoo.sync.mutex(/(^|\\)UACMutexxxxx/) or
    cuckoo.sync.mutex(/(^|\\)StikyNot_yakuza/) or
    cuckoo.sync.mutex(/(^|\\)9addd9f85a8ae7a0c5ad\.exe(M_157|\xA0M_291)2_/) >= 2 or
    cuckoo.registry.key_access(/(^|\\)Software\\VB and VBA Program Settings\\(Explorer|userinit)\\Process/) or
    cuckoo.registry.key_access(/(^|\\)SOFTWARE\\MICROSOFT\\Rpc\\Extensions\\NdrOleExtDLL/)
}
