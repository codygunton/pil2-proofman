//! Binary parser for compiled expression bytecode (.bin files).
//!
//! Parses the "chps" binary format used by pil2-stark for constraint expressions.
//! Only the expression section (section 1) is needed for verifier-mode evaluation.
//!
//! Translates: executable-spec/primitives/expression_bytecode/expressions_bin.py

use std::collections::HashMap;
use std::fs;

/// Expression metadata for a single expression.
#[derive(Debug, Clone)]
pub struct ParserParams {
    pub exp_id: u32,
    pub dest_dim: u32,
    pub n_ops: u32,
    pub ops_offset: u32,
    pub n_args: u32,
    pub args_offset: u32,
}

/// Global bytecode arrays shared across all expressions.
#[derive(Debug)]
pub struct ParserArgs {
    pub ops: Vec<u8>,
    pub args: Vec<u16>,
    pub numbers: Vec<u64>,
}

/// Parsed expression binary containing bytecode for constraint evaluation.
#[derive(Debug)]
pub struct ExpressionsBin {
    pub expressions_info: HashMap<u32, ParserParams>,
    pub expressions_args: ParserArgs,
}

impl ExpressionsBin {
    /// Load from a .bin file (chps format).
    pub fn from_file(path: &str) -> Result<Self, String> {
        let data = fs::read(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
        Self::parse(&data)
    }

    fn parse(data: &[u8]) -> Result<Self, String> {
        let mut r = BinReader::new(data)?;

        // Find expression section (section 1)
        let (sec_start, _sec_size) = r
            .sections
            .get(&1)
            .and_then(|s| s.first().copied())
            .ok_or("Missing expression section (section 1)")?;

        r.pos = sec_start;

        // Read header: max_tmp1, max_tmp3, max_args, max_ops (unused but must skip)
        let _max_tmp1 = r.read_u32()?;
        let _max_tmp3 = r.read_u32()?;
        let _max_args = r.read_u32()?;
        let _max_ops = r.read_u32()?;

        let n_ops_total = r.read_u32()? as usize;
        let n_args_total = r.read_u32()? as usize;
        let n_numbers = r.read_u32()? as usize;
        let n_expressions = r.read_u32()? as usize;

        // Read expression metadata
        let mut expressions_info = HashMap::new();
        for _ in 0..n_expressions {
            let exp_id = r.read_u32()?;
            let dest_dim = r.read_u32()?;
            let _dest_id = r.read_u32()?;
            let _stage = r.read_u32()?;
            let _n_temp1 = r.read_u32()?;
            let _n_temp3 = r.read_u32()?;
            let n_ops = r.read_u32()?;
            let ops_offset = r.read_u32()?;
            let n_args = r.read_u32()?;
            let args_offset = r.read_u32()?;
            let _line = r.read_string()?;

            expressions_info.insert(
                exp_id,
                ParserParams {
                    exp_id,
                    dest_dim,
                    n_ops,
                    ops_offset,
                    n_args,
                    args_offset,
                },
            );
        }

        // Read bytecode arrays
        let mut ops = Vec::with_capacity(n_ops_total);
        for _ in 0..n_ops_total {
            ops.push(r.read_u8()?);
        }

        let mut args = Vec::with_capacity(n_args_total);
        for _ in 0..n_args_total {
            args.push(r.read_u16()?);
        }

        let mut numbers = Vec::with_capacity(n_numbers);
        for _ in 0..n_numbers {
            numbers.push(r.read_u64()?);
        }

        Ok(ExpressionsBin {
            expressions_info,
            expressions_args: ParserArgs { ops, args, numbers },
        })
    }
}

// ============================================================================
// Binary file reader for "chps" format
// ============================================================================

struct BinReader<'a> {
    data: &'a [u8],
    pos: usize,
    sections: HashMap<u32, Vec<(usize, usize)>>,
}

impl<'a> BinReader<'a> {
    fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 4 || &data[0..4] != b"chps" {
            return Err("Invalid magic: expected 'chps'".into());
        }

        let mut r = BinReader {
            data,
            pos: 4,
            sections: HashMap::new(),
        };

        let version = r.read_u32()?;
        if version > 1 {
            return Err(format!("Unsupported version: {version}"));
        }

        let n_sections = r.read_u32()? as usize;

        for _ in 0..n_sections {
            let section_type = r.read_u32()?;
            let section_size = r.read_u64()? as usize;
            let section_start = r.pos;

            r.sections
                .entry(section_type)
                .or_default()
                .push((section_start, section_size));

            r.pos += section_size;
        }

        r.pos = 0;
        Ok(r)
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() {
            return Err("Unexpected EOF reading u8".into());
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        if self.pos + 2 > self.data.len() {
            return Err("Unexpected EOF reading u16".into());
        }
        let val = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.data.len() {
            return Err("Unexpected EOF reading u32".into());
        }
        let val = u32::from_le_bytes(
            self.data[self.pos..self.pos + 4].try_into().unwrap(),
        );
        self.pos += 4;
        Ok(val)
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        if self.pos + 8 > self.data.len() {
            return Err("Unexpected EOF reading u64".into());
        }
        let val = u64::from_le_bytes(
            self.data[self.pos..self.pos + 8].try_into().unwrap(),
        );
        self.pos += 8;
        Ok(val)
    }

    fn read_string(&mut self) -> Result<String, String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.data[start..self.pos])
            .map_err(|e| format!("Invalid UTF-8: {e}"))?
            .to_string();
        if self.pos < self.data.len() {
            self.pos += 1; // skip null terminator
        }
        Ok(s)
    }
}
