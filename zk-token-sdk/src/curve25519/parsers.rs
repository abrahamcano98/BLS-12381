
#[cfg(not(target_os = "solana"))]
pub mod target_arch {
use {
        blst::*
};


pub fn read_fp_blst(fp_bytes_be: &[u8]) -> blst_fp12 {
    let indexes = [0, 1, 4, 5, 8, 9, 2, 3, 6, 7, 10, 11];
    let mut a = blst_fp12::default();
    let mut iter = 0;
    for i in 0..2 {
        for j in 0..3 {
            for k in 0..2 {
                let mut fp = blst_fp::default();
                let num = indexes[iter];
                unsafe {
                    blst_fp_from_bendian(&mut fp, fp_bytes_be[num * 48..(num + 1) * 48].as_ptr());
                };
                a.fp6[i].fp2[j].fp[k] = fp;
                iter += 1;
            }
        }
    }
    a
}
}