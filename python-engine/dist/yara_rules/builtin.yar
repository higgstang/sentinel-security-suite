
rule suspicious_powershell_encoded
{
    strings:
        $a = /powershell[ \t]+-(enc|encodedcommand)/ nocase
        $b = /powershell[ \t]+-w[ \t]+hidden/ nocase
    condition:
        any of them
}

rule suspicious_cmd
{
    strings:
        $a = "cmd.exe /c" nocase
        $b = "cmd /c" nocase
        $c = "powershell.exe" nocase
    condition:
        any of them
}

rule eicar_test
{
    strings:
        $a = {58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2A}
    condition:
        any of them
}

rule suspicious_wscript
{
    strings:
        $a = "Wscript.Shell" nocase
        $b = "Shell.Application" nocase
        $c = "CreateObject" nocase
    condition:
        any of them
}

rule ransomware_note_pattern
{
    strings:
        $a = /all your files.*(encrypted|locked)/ nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
    condition:
        2 of them
}
