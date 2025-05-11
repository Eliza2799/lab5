rule Detect_Netmonitor_Hash {
    meta:
        description = "Detects netmonitor by SHA-256 hash"
    strings:
        $hash = "1a11d3a235fd771cb57c76b79d007f986e5d89e384e8bb7d5a639f670496dd0b" ascii
    condition:
        $hash at 0
}

rule Detect_Netmonitor_Strings {
    meta:
        description = "Detects netmonitor by strings"
    strings:
        $log = "network_monitor.log" ascii
        $perror = "perror@GLIBC" ascii
    condition:
        any of them
}

rule Detect_Netmonitor_ELF {
    meta:
        description = "Detects ELF binary with netmonitor markers"
    strings:
        $elf = { 7f 45 4c 46 }
        $log = "network_monitor.log" ascii
    condition:
        $elf at 0 and $log
}

rule Detect_Netmonitor_Size {
    meta:
        description = "Detects by size and strings"
    strings:
        $log = "network_monitor.log" ascii
    condition:
        $log and filesize == 18KB
}
rule Detect_XOR_Strings {
    meta:
        description = "Detects XOR-encoded strings (key 0x1A)"
    strings:
        $xor1 = "Gqk^Mq|g" xor(0x1A)
        $xor2 = { 47 71 6b 5e 4d 71 7c 67 } xor(0x1A)
    condition:
        any of them
}
