//! Implementation of  [`ProcessControlBlock`]

use super::id::RecycleAllocator;
use super::manager::insert_into_pid2process;
use super::TaskControlBlock;
use super::{add_task, SignalFlags};
use super::{pid_alloc, PidHandle};
use crate::fs::{File, Stdin, Stdout};
use crate::mm::{translated_refmut, MapPermission, MemorySet, VirtAddr, KERNEL_SPACE};
use crate::sync::{Condvar, Mutex, Semaphore, UPSafeCell};
use crate::syscall::MUTEX_CHECK_DEADLOCK;
use crate::trap::{trap_handler, TrapContext};
// use crate::config::TRAP_CONTEXT_BASE;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefMut;

/// Process Control Block
pub struct ProcessControlBlock {
    /// immutable
    pub pid: PidHandle,
    /// mutable
    inner: UPSafeCell<ProcessControlBlockInner>,
}

/// Inner of Process Control Block
pub struct ProcessControlBlockInner {
    /// is zombie?
    pub is_zombie: bool,
    /// memory set(address space)
    pub memory_set: MemorySet,
    /// parent process
    pub parent: Option<Weak<ProcessControlBlock>>,
    /// children process
    pub children: Vec<Arc<ProcessControlBlock>>,
    /// exit code
    pub exit_code: i32,
    /// file descriptor table
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    /// signal flags
    pub signals: SignalFlags,
    /// tasks(also known as threads)
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    /// task resource allocator
    pub task_res_allocator: RecycleAllocator,
    /// mutex list
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    /// semaphore list
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    /// condvar list
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
    /// Priority
    pub priority: usize,
    /// enable deadlock detection
    enable_deadlock_detection: isize,
    /// mutex avaliable list
    mutex_avaliable_list: Vec<Option<Arc<MutexInfo>>>,
    /// mutex allocated list
    mutex_allocated_list: Vec<Option<Arc<NeedMutexInfo>>>,
    /// mutex need list
    mutex_need_list: Vec<Option<Arc<NeedMutexInfo>>>,
    /// mutex finished list
    mutex_finished_list: Vec<Option<Arc<FinishedMutexInfo>>>,
}

struct MutexInfo {
    inner: UPSafeCell<MutexInfoInner>,
}

struct MutexInfoInner {
    /// mutex id
    id: isize,
    /// mutex count
    count: isize,
}

impl MutexInfo {
    pub fn new(id: isize, count: isize) -> Self {
        Self {
            inner: unsafe { UPSafeCell::new(MutexInfoInner { id, count }) },
        }
    }

    pub fn get_id(&self) -> isize {
        self.inner.exclusive_access().id
    }

    pub fn allocate(&self, count: isize) -> bool {
        if self.inner.exclusive_access().count >= count {
            self.inner.exclusive_access().count -= count;
            true
        } else {
            false
        }
    }

    pub fn release(&self, count: isize) {
        self.inner.exclusive_access().count += count;
    }
}

struct NeedMutexInfo {
    inner: UPSafeCell<NeedMutexInfoInner>,
}

struct NeedMutexInfoInner {
    /// tid
    tid: isize,
    /// mutex id
    mutex_info: Vec<Arc<MutexInfo>>,
}

impl NeedMutexInfo {
    pub fn new(tid: isize, mutex_info: Vec<Arc<MutexInfo>>) -> Self {
        Self {
            inner: unsafe { UPSafeCell::new(NeedMutexInfoInner { tid, mutex_info }) },
        }
    }

    pub fn get_tid(&self) -> isize {
        self.inner.exclusive_access().tid
    }

    pub fn exists_mutex(&self, id: isize) -> bool {
        self.inner
            .exclusive_access()
            .mutex_info
            .iter()
            .any(|item| item.get_id() == id)
    }

    pub fn add_mutex_info(&self, mutex_info: Arc<MutexInfo>) {
        self.inner.exclusive_access().mutex_info.push(mutex_info);
    }

    pub fn remove_mutex_info(&self, mutex_id: isize) -> bool {
        let mut inner = self.inner.exclusive_access();

        if let Some(pos) = inner
            .mutex_info
            .iter()
            .position(|item| item.get_id() == mutex_id)
        {
            inner.mutex_info.remove(pos);
            return true;
        }

        false
    }
}

struct FinishedMutexInfo {
    inner: UPSafeCell<FinishedMutexInfoInner>,
}

struct FinishedMutexInfoInner {
    /// mutex name
    pub tid: isize,
    /// mutex count
    pub is_finished: bool,
}

impl FinishedMutexInfo {
    pub fn new(tid: isize, is_finished: bool) -> Self {
        Self {
            inner: unsafe { UPSafeCell::new(FinishedMutexInfoInner { tid, is_finished }) },
        }
    }

    pub fn get_tid(&self) -> isize {
        self.inner.exclusive_access().tid
    }

    pub fn is_finished(&self) -> bool {
        self.inner.exclusive_access().is_finished
    }

    pub fn set_finished(&self, is_finished: bool) {
        self.inner.exclusive_access().is_finished = is_finished;
    }
}

impl ProcessControlBlockInner {
    #[allow(unused)]
    /// get the address of app's page table
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    /// allocate a new file descriptor
    pub fn alloc_fd(&mut self) -> usize {
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            fd
        } else {
            self.fd_table.push(None);
            self.fd_table.len() - 1
        }
    }
    /// allocate a new task id
    pub fn alloc_tid(&mut self) -> usize {
        self.task_res_allocator.alloc()
    }
    /// deallocate a task id
    pub fn dealloc_tid(&mut self, tid: usize) {
        self.task_res_allocator.dealloc(tid)
    }
    /// the count of tasks(threads) in this process
    pub fn thread_count(&self) -> usize {
        self.tasks.len()
    }
    /// get a task with tid in this process
    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.tasks[tid].as_ref().unwrap().clone()
    }

    pub fn init_mutex_list(&mut self, mutex_id: isize, mutex_count: isize) -> isize {
        if self.enable_deadlock_detection != 1 {
            return 0;
        }

        if self
            .mutex_avaliable_list
            .iter()
            .filter_map(|item| item.as_ref())
            .any(|item| item.get_id() == mutex_id)
        {
            return 0;
        } else {
            self.mutex_avaliable_list
                .push(Some(Arc::new(MutexInfo::new(mutex_id, mutex_count))));
        }

        0
    }

    pub fn try_lock(&mut self, tid: isize, mutex_id: isize, mutex_count: isize) -> isize {
        if self.enable_deadlock_detection != 1 {
            return 0;
        }

        // find need or init
        if let Some(need_info) = self
            .mutex_need_list
            .iter_mut()
            .filter_map(|item| item.as_mut())
            .find(|item| item.get_tid() == tid)
        {
            // init mutex_info
            if !need_info.exists_mutex(mutex_id) {
                need_info.add_mutex_info(Arc::new(MutexInfo::new(mutex_id, mutex_count)));
            }
        } else {
            // init need
            self.mutex_need_list.push(Some(Arc::new(NeedMutexInfo::new(
                tid,
                vec![Arc::new(MutexInfo::new(mutex_id, mutex_count))],
            ))));
        }

        // find finished or init
        if let Some(finished_info) = self
            .mutex_finished_list
            .iter_mut()
            .filter_map(|item| item.as_mut())
            .find(|item| item.get_tid() == tid)
        {
            if finished_info.is_finished() {
                return 0;
            }
        } else {
            // init finished
            self.mutex_finished_list
                .push(Some(Arc::new(FinishedMutexInfo::new(tid, false))));
        }

        // find available
        if let Some(available_info) = self
            .mutex_avaliable_list
            .iter_mut()
            .filter_map(|item| item.as_mut())
            .find(|item| item.get_id() == mutex_id)
        {
            let mutex_info = available_info.clone();
            if available_info.allocate(mutex_count) {
                self.mutex_allocated_list
                    .push(Some(Arc::new(NeedMutexInfo::new(tid, vec![mutex_info]))));
                return 0;
            }
        }
        // check finished
        if self
            .mutex_finished_list
            .iter()
            .filter_map(|item| item.as_ref())
            .all(|info| info.is_finished())
        {
            0
        } else {
            MUTEX_CHECK_DEADLOCK
        }
    }

    pub fn mutex_release(&mut self, tid: isize, mutex_id: isize, mutex_count: isize) -> isize {
        if self.enable_deadlock_detection != 1 {
            return 0;
        }

        if let Some(allocated_info) = self
            .mutex_allocated_list
            .iter_mut()
            .filter_map(|item| item.as_mut())
            .find(|item| item.get_tid() == tid)
        {
            if allocated_info.remove_mutex_info(mutex_id) {
                if let Some(available_info) = self
                    .mutex_avaliable_list
                    .iter_mut()
                    .filter_map(|item| item.as_mut())
                    .find(|item| item.get_id() == mutex_id)
                {
                    available_info.release(mutex_count);
                }
                // 修改 finished_list 中的 is_finished 状态
                if let Some(finished_info) = self
                    .mutex_finished_list
                    .iter_mut()
                    .filter_map(|item| item.as_mut())
                    .find(|item| item.get_tid() == tid)
                {
                    finished_info.set_finished(true);
                }
            }
        }

        0
    }
}

impl ProcessControlBlock {
    /// inner_exclusive_access
    pub fn inner_exclusive_access(&self) -> RefMut<'_, ProcessControlBlockInner> {
        self.inner.exclusive_access()
    }
    /// new process from elf file
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        trace!("kernel: ProcessControlBlock::new");
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        // allocate a pid
        let pid_handle = pid_alloc();
        let process = Arc::new(Self {
            pid: pid_handle,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
                    parent: None,
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: vec![
                        // 0 -> stdin
                        Some(Arc::new(Stdin)),
                        // 1 -> stdout
                        Some(Arc::new(Stdout)),
                        // 2 -> stderr
                        Some(Arc::new(Stdout)),
                    ],
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    priority: 16 as usize,
                    enable_deadlock_detection: 0,
                    mutex_avaliable_list: Vec::new(),
                    mutex_allocated_list: Vec::new(),
                    mutex_need_list: Vec::new(),
                    mutex_finished_list: Vec::new(),
                })
            },
        });
        // create a main thread, we should allocate ustack and trap_cx here
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&process),
            ustack_base,
            true,
        ));
        // prepare trap_cx of main thread
        let task_inner = task.inner_exclusive_access();
        let trap_cx = task_inner.get_trap_cx();
        let ustack_top = task_inner.res.as_ref().unwrap().ustack_top();
        let kstack_top = task.kstack.get_top();
        drop(task_inner);
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            ustack_top,
            KERNEL_SPACE.exclusive_access().token(),
            kstack_top,
            trap_handler as usize,
        );
        // add main thread to the process
        let mut process_inner = process.inner_exclusive_access();
        process_inner.tasks.push(Some(Arc::clone(&task)));
        drop(process_inner);
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
        // add main thread to scheduler
        add_task(task);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>) {
        trace!("kernel: exec");
        assert_eq!(self.inner_exclusive_access().thread_count(), 1);
        // memory_set with elf program headers/trampoline/trap context/user stack
        trace!("kernel: exec .. MemorySet::from_elf");
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        // substitute memory_set
        trace!("kernel: exec .. substitute memory_set");
        self.inner_exclusive_access().memory_set = memory_set;
        // then we alloc user resource for main thread again
        // since memory_set has been changed
        trace!("kernel: exec .. alloc user resource for main thread again");
        let task = self.inner_exclusive_access().get_task(0);
        let mut task_inner = task.inner_exclusive_access();
        task_inner.res.as_mut().unwrap().ustack_base = ustack_base;
        task_inner.res.as_mut().unwrap().alloc_user_res();
        task_inner.trap_cx_ppn = task_inner.res.as_mut().unwrap().trap_cx_ppn();
        // push arguments on user stack
        trace!("kernel: exec .. push arguments on user stack");
        let mut user_sp = task_inner.res.as_mut().unwrap().ustack_top();
        user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
        let argv_base = user_sp;
        let mut argv: Vec<_> = (0..=args.len())
            .map(|arg| {
                translated_refmut(
                    new_token,
                    (argv_base + arg * core::mem::size_of::<usize>()) as *mut usize,
                )
            })
            .collect();
        *argv[args.len()] = 0;
        for i in 0..args.len() {
            user_sp -= args[i].len() + 1;
            *argv[i] = user_sp;
            let mut p = user_sp;
            for c in args[i].as_bytes() {
                *translated_refmut(new_token, p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(new_token, p as *mut u8) = 0;
        }
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();
        // initialize trap_cx
        trace!("kernel: exec .. initialize trap_cx");
        let mut trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            task.kstack.get_top(),
            trap_handler as usize,
        );
        trap_cx.x[10] = args.len();
        trap_cx.x[11] = argv_base;
        *task_inner.get_trap_cx() = trap_cx;
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
        trace!("kernel: fork");
        let mut parent = self.inner_exclusive_access();
        assert_eq!(parent.thread_count(), 1);
        // clone parent's memory_set completely including trampoline/ustacks/trap_cxs
        let memory_set = MemorySet::from_existed_user(&parent.memory_set);
        // alloc a pid
        let pid = pid_alloc();
        // copy fd table
        let mut new_fd_table: Vec<Option<Arc<dyn File + Send + Sync>>> = Vec::new();
        for fd in parent.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        // create child process pcb
        let child = Arc::new(Self {
            pid,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
                    parent: Some(Arc::downgrade(self)),
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: new_fd_table,
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    priority: 16 as usize,
                    enable_deadlock_detection: 0,
                    mutex_avaliable_list: Vec::new(),
                    mutex_allocated_list: Vec::new(),
                    mutex_need_list: Vec::new(),
                    mutex_finished_list: Vec::new(),
                })
            },
        });
        // add child
        parent.children.push(Arc::clone(&child));
        // create main thread of child process
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&child),
            parent
                .get_task(0)
                .inner_exclusive_access()
                .res
                .as_ref()
                .unwrap()
                .ustack_base(),
            // here we do not allocate trap_cx or ustack again
            // but mention that we allocate a new kstack here
            false,
        ));
        // attach task to child process
        let mut child_inner = child.inner_exclusive_access();
        child_inner.tasks.push(Some(Arc::clone(&task)));
        drop(child_inner);
        // modify kstack_top in trap_cx of this thread
        let task_inner = task.inner_exclusive_access();
        let trap_cx = task_inner.get_trap_cx();
        trap_cx.kernel_sp = task.kstack.get_top();
        drop(task_inner);
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        // add this thread to scheduler
        add_task(task);
        child
    }
    /// get pid
    pub fn getpid(&self) -> usize {
        self.pid.0
    }

    /// enable deadlock detection
    pub fn enable_deadlock_detection(&self, is_enable: isize) -> isize {
        let mut inner = self.inner_exclusive_access();
        if is_enable != 0 && is_enable != 1 {
            -1
        } else {
            inner.enable_deadlock_detection = is_enable;
            0
        }
    }

    /// set priority. return None if failed.
    pub fn set_priority(&self, priority: isize) -> Option<isize> {
        if priority < 2 {
            return None;
        }
        let mut inner = self.inner_exclusive_access();
        inner.priority = priority as usize;
        Some(priority)
    }

    /// mmap. return None if failed.
    pub fn mmap(&self, start: usize, len: usize, port: usize) -> Option<usize> {
        let start_va = VirtAddr::from(start);
        let end_va = VirtAddr::from(start + len);
        let perm = ((port << 1) as u8 | 0b0001_0000) & 0b0001_1110;
        if let Some(permission) = MapPermission::from_bits(perm) {
            let mut inner = self.inner_exclusive_access();
            inner.memory_set.mmap(start_va, end_va, permission)
        } else {
            None
        }
    }

    /// munmap. return None if failed.
    pub fn munmap(&self, start: usize, len: usize) -> Option<usize> {
        let start_va = VirtAddr::from(start);
        let end_va = VirtAddr::from(start + len);
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        let mut inner = self.inner_exclusive_access();
        inner.memory_set.munmap(start_vpn, end_vpn)
    }

    pub fn spawn(self: &Arc<Self>, elf_data: &[u8]) -> Arc<Self> {
        // ---- access parent PCB exclusively
        let mut parent_inner = self.inner_exclusive_access();
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let mut new_fd_table: Vec<Option<Arc<dyn File + Send + Sync>>> = Vec::new();
        for fd in parent_inner.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        let child = Arc::new(Self {
            pid: pid_handle,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
                    parent: Some(Arc::downgrade(self)),
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: new_fd_table,
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    priority: 16 as usize,
                    enable_deadlock_detection: 0,
                    mutex_avaliable_list: Vec::new(),
                    mutex_allocated_list: Vec::new(),
                    mutex_need_list: Vec::new(),
                    mutex_finished_list: Vec::new(),
                })
            },
        });
        // add child
        parent_inner.children.push(child.clone());
        let task = Arc::new(TaskControlBlock::new(Arc::clone(&child), user_sp, true));
        let mut task_inner = task.inner_exclusive_access();
        let trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            task.kstack.get_top(),
            trap_handler as usize,
        );
        task_inner.trap_cx_ppn = task_inner.res.as_mut().unwrap().trap_cx_ppn();
        *task_inner.get_trap_cx() = trap_cx;
        drop(task_inner);
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        child
    }
}
