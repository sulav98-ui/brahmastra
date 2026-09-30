/* BRAHMASTRA EDR — demo YARA rules */

rule Brahmastra_ReverseShell_Bash {
    meta:
        description = "Bash/netcat reverse-shell one-liners"
    strings:
        $a = "bash -i >& /dev/tcp/" ascii
        $b = "/dev/tcp/" ascii
        $c = "nc -e /bin/sh" ascii
        $d = "nc -e /bin/bash" ascii
        $e = "sh -i >& /dev/tcp/" ascii
    condition:
        any of them
}

rule Brahmastra_EICAR_TestFile {
    meta:
        description = "EICAR antivirus test string (harmless)"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Brahmastra_WebShell_PHP {
    meta:
        description = "Common PHP web-shell patterns"
    strings:
        $a = "eval(base64_decode(" ascii
        $b = "system($_GET[" ascii
        $c = "shell_exec($_" ascii
        $d = "passthru($_" ascii
    condition:
        any of them
}
