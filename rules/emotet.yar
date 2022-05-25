import "cuckoo"

rule Emotet
{
  condition:
    cuckoo.sync.mutex(/(^|\\)[IM]5C3A8244/) >= 2 or
    cuckoo.sync.mutex(/(^|\\)PEM[0-9A-F]{2,3}/) or
    cuckoo.sync.mutex(/(^|\\)Nx6C4BA8F9/) or
    cuckoo.sync.mutex(/(^|\\)(MB0B7DDA9|MB7DD1991)/)
}
