// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This should go in either 'sys' or 'os'
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
fn cpuid(func: u32) -> (u32, u32, u32, u32) {
    let mut a = 0u32;
    let mut b = 0u32;
    let mut c = 0u32;
    let mut d = 0u32;

    unsafe {
        asm!(
        "
        movl $4, %eax;
        cpuid;
        movl %eax, $0;
        movl %ebx, $1;
        movl %ecx, $2;
        movl %edx, $3;
        "
        : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
        : "r" (func)
        : "eax", "ebx", "ecx", "edx"
        : "volatile"
        )
    }

    return (a, b, c, d);
}

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn supports_aesni() -> bool {
    let (_, _, c, _) = cpuid(1);
    return (c & 0x02000000) != 0;
}
