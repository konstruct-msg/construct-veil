use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
pub struct Counting;
pub static ALLOCS: AtomicU64 = AtomicU64::new(0);
pub static BYTES: AtomicU64 = AtomicU64::new(0);
pub static LIVE: AtomicI64 = AtomicI64::new(0);
pub static PEAK: AtomicI64 = AtomicI64::new(0);
fn add(n: usize) {
    ALLOCS.fetch_add(1, Relaxed);
    BYTES.fetch_add(n as u64, Relaxed);
    let l = LIVE.fetch_add(n as i64, Relaxed) + n as i64;
    PEAK.fetch_max(l, Relaxed);
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        add(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        add(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_sub(l.size() as i64, Relaxed);
        add(n);
        unsafe { System.realloc(p, l, n) }
    }
}
#[derive(Clone, Copy)]
pub struct Snap {
    pub allocs: u64,
    pub bytes: u64,
    pub live: i64,
    pub threads: usize,
    pub fds: usize,
    pub cpu_us: u64,
    pub iwk: u64,
    pub idlewk: u64,
    pub footprint: u64,
    pub diskw: u64,
}
unsafe extern "C" {
    fn task_threads(t: libc::mach_port_t, l: *mut *mut libc::thread_act_t, c: *mut u32) -> i32;
}
#[allow(deprecated)]
pub fn snap() -> Snap {
    unsafe {
        let (mut l, mut c) = (std::ptr::null_mut(), 0u32);
        task_threads(libc::mach_task_self(), &mut l, &mut c);
        libc::vm_deallocate(libc::mach_task_self(), l as _, c as usize * 4);
        let mut r: libc::rusage_info_v4 = std::mem::zeroed();
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            &mut r as *mut _ as *mut _,
        );
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        let cpu = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
        let fds = (0..4096)
            .filter(|&f| libc::fcntl(f, libc::F_GETFD) != -1)
            .count();
        Snap {
            allocs: ALLOCS.load(Relaxed),
            bytes: BYTES.load(Relaxed),
            live: LIVE.load(Relaxed),
            threads: c as usize,
            fds,
            cpu_us: cpu(ru.ru_utime) + cpu(ru.ru_stime),
            iwk: r.ri_interrupt_wkups,
            idlewk: r.ri_pkg_idle_wkups,
            footprint: r.ri_phys_footprint,
            diskw: r.ri_diskio_byteswritten,
        }
    }
}
pub fn show(label: &str, a: Snap, b: Snap) {
    println!(
        "{label:<34} allocs {:>7} alloc {:>8.1} KB live {:>+8.1} KB threads {:>+3} (={}) fds {:>+3} cpu {:>7.1} ms wake {:>5} idlewake {:>4} footprint {:>+8.0} KB diskw {} KB",
        b.allocs - a.allocs,
        (b.bytes - a.bytes) as f64 / 1024.,
        (b.live - a.live) as f64 / 1024.,
        b.threads as i64 - a.threads as i64,
        b.threads,
        b.fds as i64 - a.fds as i64,
        (b.cpu_us - a.cpu_us) as f64 / 1000.,
        b.iwk - a.iwk,
        b.idlewk - a.idlewk,
        (b.footprint as f64 - a.footprint as f64) / 1024.,
        (b.diskw - a.diskw) / 1024
    );
}
