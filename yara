rule parallax_rats_panel_exe_injection {
meta:
        description = "Identibinary the Parallax"
        author = "FEVAR54"
    strings:
        $payload1 = "c:\\windows\\temp\\payload1.exe"
        $payload2 = "c:\\windows\\temp\\payload2.exe"
        $legit_process = "c:\\windows\\system32\\imageres.dll"
        $injected_process = "c:\\windows\\system32\\pipanel.exe"
    condition:
        all of ($payload1, $payload2, $legit_process, $injected_process) and
        uint16(0) == 0x5a4d and // MZ header
        any of ($payload1, $payload2): uint32(uint32(0x3C)) == 0x00004550 and // EP header
        $legit_process fullword ascii and
        $injected_process fullword ascii and
        any of them
}
