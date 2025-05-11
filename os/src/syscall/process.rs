//! Process management syscalls
use crate::{
    config::PAGE_SIZE,
    mm::{translated_byte_buffer_with_err, write_data_2_user, write_data_2_user_with_err},
    syscall::{
        SYSCALL_GET_TIME, SYSCALL_MMAP, SYSCALL_MUNMAP, SYSCALL_SBRK, SYSCALL_TRACE, SYSCALL_YIELD,
    },
    task::{
        change_program_brk, count_syscall, current_user_token, exit_current_and_run_next,
        get_sys_call_count, map, suspend_current_and_run_next, unmap,
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    count_syscall(SYSCALL_YIELD);
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    count_syscall(SYSCALL_GET_TIME);
    // info!(" ======================================= kernel: sys_get_time");
    let us = get_time_us();
    let data = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let ptr = &data as *const TimeVal as *const u8;
    let len = core::mem::size_of::<TimeVal>();
    let data: &[u8] = unsafe { core::slice::from_raw_parts(ptr, len) };
    write_data_2_user(current_user_token(), ts as *const u8, data);
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    info!(
        "========================= kernel: sys_trace, request: {:?}, id: {:?}, data: {:?}",
        trace_request,
        id,
        data
    );
    let result = count_syscall(SYSCALL_TRACE);
    match trace_request {
        0 => {
            if let Some(buffers) =
                translated_byte_buffer_with_err(current_user_token(), id as *const u8, 1)
            {
                let result = buffers[0][0];
                return result as isize;
            } else {
                -1 as isize
            }
        }
        1 => {
            if let None =
                write_data_2_user_with_err(current_user_token(), id as *mut u8, &[data as u8])
            {
                return -1 as isize;
            }
            return 0;
        }
        2 => {
            if id != SYSCALL_TRACE {
                get_sys_call_count(id)
            } else {
                result
            }
        }
        _ => -1 as isize,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("========================= kernel: sys_mmap");
    count_syscall(SYSCALL_MMAP);
    trace!(
        "========================= kernel: sys_mmap start: {:?}, len: {:?}, prot: {:?}",
        start,
        len,
        prot
    );
    if valid_addr(start) && valid_prot(prot) && map(start, len, prot) {
        0
    } else {
        -1
    }
}

fn valid_addr(start: usize) -> bool {
    start % PAGE_SIZE == 0
}

fn valid_prot(prot: usize) -> bool {
    (prot & !0x7) == 0 && (prot & 0x7) != 0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("========================= kernel: sys_munmap");
    count_syscall(SYSCALL_MUNMAP);
    if valid_addr(start) && unmap(start, len) {
        0
    } else {
        -1
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    count_syscall(SYSCALL_SBRK);
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
