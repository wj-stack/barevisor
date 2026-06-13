//! Minimal x86-64 instruction-length decoder for EPT hook patch sizing.
//!
//! Matches TinyVT `GetWriteCodeLen`: walk complete instructions until at least
//! `minimum` bytes are covered.

/// Returns how many bytes from `offset` span complete instructions totaling >= `minimum`.
pub(crate) fn patch_len_at_least(bytes: &[u8], offset: usize, minimum: usize) -> Option<usize> {
    if minimum == 0 || offset >= bytes.len() {
        return None;
    }
    let mut total = 0usize;
    let mut pos = offset;
    while total < minimum {
        let len = instruction_length(bytes.get(pos..)?)?;
        total += len;
        pos += len;
        if total > 64 {
            return None;
        }
    }
    Some(total)
}

fn instruction_length(code: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < code.len() && is_legacy_prefix(code[i]) {
        i += 1;
    }
    if i < code.len() && (code[i] & 0xF0) == 0x40 {
        i += 1;
    }
    let start = i;
    let opcode = *code.get(i)?;
    i += 1;

    if opcode == 0x0F {
        let op2 = *code.get(i)?;
        i += 1;
        return match op2 {
            0x05 => Some(i - start), // syscall
            0x1F => {
                // nop / multibyte nop with modrm
                i += modrm_sib_disp(code.get(i..)?)?;
                Some(i - start)
            }
            _ => None,
        };
    }

    match opcode {
        0xC3 => Some(i - start),
        0xC2 => Some(i + 2 - start),
        0x68 => Some(i + if has_operand_size_prefix(code, start) { 2 } else { 4 } - start),
        0x6A => Some(i + 1 - start),
        0xB8..=0xBF => Some(i + 4 - start), // mov r32/64, imm32
        0xE8 | 0xE9 => Some(i + 4 - start), // call/jmp rel32
        0xEB => Some(i + 1 - start),
        0x80..=0x83 => {
            i += modrm_sib_disp(code.get(i..)?)?;
            i += 1; // imm8
            Some(i - start)
        }
        0x88..=0x8B | 0x38..=0x3B => {
            i += modrm_sib_disp(code.get(i..)?)?;
            Some(i - start)
        }
        0xFF => {
            i += modrm_sib_disp(code.get(i..)?)?;
            let reg = (code.get(start + 1)? >> 3) & 7;
            if reg == 2 || reg == 4 {
                i += 2; // call/jmp far indirect — rare
            }
            Some(i - start)
        }
        _ => None,
    }
}

fn has_operand_size_prefix(code: &[u8], opcode_pos: usize) -> bool {
    code[..opcode_pos].contains(&0x66)
}

fn is_legacy_prefix(byte: u8) -> bool {
    matches!(
        byte,
        0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65
    )
}

fn modrm_sib_disp(code: &[u8]) -> Option<usize> {
    let modrm = *code.first()?;
    let mod_field = modrm >> 6;
    let rm = modrm & 7;
    let mut size = 1usize;

    if mod_field == 3 {
        return Some(size);
    }

    if rm == 4 {
        size += 1; // SIB
        let base = code.get(1).copied().unwrap_or(0) & 7;
        if mod_field == 0 && base == 5 {
            size += 4;
        }
    } else if mod_field == 0 && rm == 5 {
        size += 4;
    }

    match mod_field {
        1 => size += 1,
        2 => size += 4,
        _ => {}
    }
    Some(size)
}

#[cfg(test)]
mod tests {
    use super::patch_len_at_least;

    #[test]
    fn nt_open_process_prologue_is_thirteen_bytes() {
        let bytes = [
            0x48, 0x83, 0xEC, 0x38, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x44,
            0x8A, 0x90,
        ];
        assert_eq!(patch_len_at_least(&bytes, 0, 12), Some(13));
    }
}
