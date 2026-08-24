// ============================================================================
//  SentinelX — Shellcode Patterns
//  file: shellcode_patterns.yar
//
//  Generic x86/x64 shellcode structure patterns. These match the *shape*
//  of position-independent shellcode found in the wild:
//
//   - NOP sleds          (90 90 90 ...) — slide into the payload
//   - INT3 sleds         (CC CC CC ...) — used by some droppers to mark
//                                         the payload boundary
//   - jmp/call/pop pivot (EB 05 E8 F9 FF FF FF 5A) — the canonical
//                                         shellcode entry: jump forward,
//                                         call back, pop the payload base
//
//  Note on tuning: shellcode in transit is usually encrypted (second
//  stage). These rules catch PLAINTEXT stage-1 payloads — the most
//  common form in memory-spraying and exploit-kit test traffic.
// ============================================================================

rule shellcode_nop_sled
{
    meta:
        description = "NOP sled — at least 10 consecutive 0x90 bytes"
        severity    = "HIGH"
        mitre       = "T1059"
        mitre_name  = "Command and Scripting Interpreter"
        author      = "SentinelX"
        reference   = "https://www.owasp.org/index.php/NOP_Sled"

    strings:
        $nop10 = { 90 90 90 90 90 90 90 90 90 90 }
        // 16-byte sled with a small middle gap (common obfuscation)
        $nop_gap = { 90 90 90 90 [2-4] 90 90 90 90 90 }

    condition:
        any of them
}


rule shellcode_int3_sled
{
    meta:
        description = "INT3 sled — at least 12 consecutive 0xCC bytes"
        severity    = "MEDIUM"
        mitre       = "T1059"
        mitre_name  = "Command and Scripting Interpreter"
        author      = "SentinelX"
        reference   = "https://en.wikipedia.org/wiki/Breakpoint_(software)"

    strings:
        $int3_12 = { CC CC CC CC CC CC CC CC CC CC CC CC }

    condition:
        $int3_12
}


rule shellcode_jmp_call_pop_pivot
{
    meta:
        description = "x86 jmp/call/pop shellcode entry pivot"
        severity    = "HIGH"
        mitre       = "T1059"
        mitre_name  = "Command and Scripting Interpreter"
        author      = "SentinelX"
        reference   = "https://www.exploit-db.com/papers/13113"

    strings:
        // jmp short +5 ; call -5 ; pop reg  (5A = pop esi, 5B = pop ebx)
        $pivot_esi = { EB 05 E8 F9 FF FF FF 5A }
        $pivot_ebx = { EB 05 E8 F9 FF FF FF 5B }
        // 64-bit variant: push rsi ; mov rsi, [rsp]
        $pivot64   = { 48 89 E6 }

    condition:
        any of them
}
