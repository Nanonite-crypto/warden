/*
    Warden's built-in YARA rules.

    These are compiled into the program and are always active. They cover
    test files only. Detection of real threats comes from rule bundles,
    which are built from rule sets you choose; see docs/RULES.md.

    Metadata that Warden reads:
      threat_name   the name a match is reported under (default: the rule name)
      category      "malware" (default), "test_file" or "potentially_unwanted"
      score         0 to 100: 80 and above is reported as malicious,
                    60 to 79 as suspicious, anything lower is only recorded
      description   shown as the reason for the detection
*/

rule Warden_EICAR_Test_File
{
    meta:
        threat_name = "EICAR-Test-File"
        description = "the EICAR antivirus test file, a harmless file that every scanner detects on purpose"
        category = "test_file"
        score = 100
        author = "Vevang Technologies"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        // The test string is written in two parts, so that neither this
        // file nor a program it is built into contains the whole string.
        // Other antivirus products would report them as the test file.
        $first = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
        $second = "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        // The definition of the test file: the 68 characters at the very
        // start, followed by nothing but whitespace, 128 bytes at most.
        filesize >= 68 and filesize <= 128
        and $first at 0 and $second at 33
        and (
            filesize == 68
            or for all i in (68 .. filesize - 1) : (
                uint8(i) == 0x20 or uint8(i) == 0x09 or uint8(i) == 0x0A
                or uint8(i) == 0x0D or uint8(i) == 0x1A
            )
        )
}
