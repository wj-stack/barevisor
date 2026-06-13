//! Prints virtual addresses of three functions, then dispatches on user input.
//!
//! Example:
//! ```text
//! hook_example
//! # note addresses printed at startup, then:
//! 1
//! 2
//! o
//! q
//! ```

use std::io::{self, Write};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

#[inline(never)]
fn function_a() {
    println!("A");
}

#[inline(never)]
fn function_b() {
    println!("B");
}

#[inline(never)]
fn function_c() {
    println!("C");
}

fn probe_open_process() {
    let pid = unsafe { GetCurrentProcessId() };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    match handle {
        Ok(h) => {
            println!("OpenProcess(pid={pid}) ok, handle={h:?}");
            unsafe {
                let _ = CloseHandle(h);
            }
        }
        Err(error) => {
            println!("OpenProcess(pid={pid}) failed: {error}");
        }
    }
}

fn main() {
    let addr_a = function_a as *const () as usize;
    let addr_b = function_b as *const () as usize;
    let addr_c = function_c as *const () as usize;

    println!("Function virtual addresses:");
    println!("  A (function_a) = {addr_a:#018x}");
    println!("  B (function_b) = {addr_b:#018x}");
    println!("  C (function_c) = {addr_c:#018x}");
    println!();
    println!("Enter 1/2/3 to call A/B/C, o to OpenProcess (SSDT hook test), or q to quit.");

    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush().ok();

        let mut line = String::new();
        if stdin.read_line(&mut line).is_err() {
            break;
        }

        match line.trim() {
            "1" => function_a(),
            "2" => function_b(),
            "3" => function_c(),
            "o" | "O" => probe_open_process(),
            "q" | "Q" => break,
            "" => {}
            other => println!("Unknown choice: {other:?} (use 1, 2, 3, o, or q)"),
        }
    }
}
