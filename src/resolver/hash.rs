use core::ffi::CStr;

/*
uint32_t gnu_hash(const uint8_t* name) {
    uint32_t h = 5381;

    for (; *name; name++) {
        h = (h << 5) + h + *name;
    }

    return h;
}
*/

#[inline(always)]
pub fn gnu_hash(name: &CStr) -> u32 {
    name.bytes().fold(5381, |v, i| {
        v.wrapping_shl(5).wrapping_add(v).wrapping_add(i as u32)
    })
}

#[inline(always)]
pub fn svr4_hash(name: &CStr) -> u32 {
    name.bytes().fold(0, |v, i| {
        let mut h = (v << 4).wrapping_add(i as u32);

        let g = h & 0xF0000000;

        h ^= g >> 24;

        h &= !g;

        h
    })
}
