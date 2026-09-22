// Example YARA rules for detecting shellcode payloads embedded in a
// scanned file - not tied to one specific RealFileType, since shellcode
// gets smuggled inside documents, images, and other non-executable
// containers just as often as standalone executables. See #5. Not wired
// into malware.rs yet - see rules/README.md.

// A long run of NOP (0x90) bytes is the classic shellcode "sled" -
// padding placed before the real payload so an imprecise jump into
// anywhere in the sled still slides into the payload. 32 consecutive
// NOPs is a common rule-of-thumb threshold; legitimate code essentially
// never has runs this long (alignment padding is usually just a handful
// of bytes).
rule shellcode_nop_sled
{
    meta:
        description = "Long run of 0x90 (NOP) bytes -- classic shellcode NOP sled"
        severity    = "medium"
        target      = "generic - any file type"

    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                      90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        $nop_sled
}

// GetPC idioms: position-independent shellcode can't hardcode its own
// address, so it computes it at runtime. `call $+5` followed by a `pop`
// is the most common x86 way to grab the current instruction pointer off
// the stack into a register.
rule shellcode_getpc_call_pop
{
    meta:
        description = "x86 call/pop GetPC idiom used by position-independent shellcode to find its own address"
        severity    = "medium"
        target      = "generic - any file type"

    strings:
        // E8 00 00 00 00 = call $+5 (calls the very next instruction);
        // 58-5F = pop eax..edi, whichever register the shellcode grabs
        // its address into. Allows a few bytes of slack in between for
        // variants that stash something else first.
        $call_pop = { E8 00 00 00 00 [0-4] 5? }

    condition:
        $call_pop
}

// The FPU-based GetPC variant, an alternative to call/pop that pulls the
// instruction pointer out of the saved FPU environment instead - common
// in polymorphic shellcode encoders (including Metasploit's
// shikata_ga_nai) specifically because it never touches the stack.
rule shellcode_getpc_fpu
{
    meta:
        description = "x86 FPU-based GetPC idiom (fldz/fnstenv) used by polymorphic shellcode encoders"
        severity    = "medium"
        target      = "generic - any file type"

    strings:
        // D9EE = fldz (loads a harmless 0.0 so the FPU has a defined
        // state to save); D97424F4 = fnstenv [esp-0xC], which dumps the
        // FPU environment -- including the last-executed instruction's
        // address -- onto the stack; 5? = the pop that retrieves it.
        $fpu_getpc = { D9 EE D9 74 24 F4 5? }

    condition:
        $fpu_getpc
}

// The egghunter technique - a tiny stub that searches memory for a
// repeated marker ("egg") to find and jump to the real, larger payload
// staged elsewhere. 0x50905090 is the de facto standard egg tag from
// skape/jduck's original egghunter, reused verbatim by most public
// shellcode generators (including Metasploit's own egghunter payloads).
// The hunter's own comparison code encodes the tag twice, and the staged
// payload it's searching for is itself prefixed with two more copies --
// so requiring at least 2 hits (rather than 1) cuts down on matching a
// single incidental occurrence of the bytes.
rule shellcode_egghunter_tag
{
    meta:
        description = "Default egghunter tag (0x50905090) marking a staged shellcode payload"
        severity    = "high"
        target      = "generic - any file type"

    strings:
        $egg = { 50 90 50 90 }

    condition:
        #egg >= 2
}
