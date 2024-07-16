use super::{Completion, File, WriteCompletion, IO};
use anyhow::{ensure, Result};
use libc::iovec;
use log::{debug, trace};
use std::cell::RefCell;
use nix::fcntl::{FcntlArg, OFlag};
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::fmt;
use thiserror::Error;

const MAX_IOVECS: usize = 128;

#[derive(Debug, Error)]
enum LinuxIOError {
    IOUringCQError(i32),
}

// Implement the Display trait to customize error messages
impl fmt::Display for LinuxIOError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinuxIOError::IOUringCQError(code) => write!(f, "IOUring completion queue error occurred with code {}", code),
        }
    }
}

pub struct LinuxIO {
    inner: Rc<RefCell<InnerLinuxIO>>,
}

pub struct InnerLinuxIO {
    ring: io_uring::IoUring,
    iovecs: [iovec; MAX_IOVECS],
    free_io_vec_idx: [u8; MAX_IOVECS/8], //bitmap to keep track of the iovecs that are available for a SQ to take.
}

impl LinuxIO {
    pub fn new() -> Result<Self> {
        let ring = io_uring::IoUring::new(MAX_IOVECS as u32)?;
        let inner = InnerLinuxIO {
            ring: ring,
            iovecs: [iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_IOVECS],
            free_io_vec_idx: [0; MAX_IOVECS / 8],
        };
        Ok(Self {
            inner: Rc::new(RefCell::new(inner)),
        })
    }
}

// Define a custom error type
#[derive(Debug)]
struct ExhaustedIOVecError(String);

impl fmt::Display for ExhaustedIOVecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExhaustedIOVecError Error")
    }
}


struct ReadCompletionWrapped {
    // I expect that the pointer to CompletionWrapped also points to Completion so that IOUring can read/write into/from the buffer
    completion: Rc<Completion>,
    io_vec_idx: usize, 
}

struct WriteCompletionWrapped {
    // I expect that the pointer to CompletionWrapped also points to Completion so that IOUring can read/write into/from the buffer
    completion: Rc<WriteCompletion>,
    io_vec_idx: usize, 
}
impl InnerLinuxIO {
    fn get_next_free_iovec_slot(&self) -> Result<usize, ExhaustedIOVecError> {
        let mut free_idx = 0;
        while free_idx != MAX_IOVECS { // if it has gone through all candidates it should fail
            let byte_index = (free_idx % MAX_IOVECS) / 8;
            let bit_index = (free_idx % MAX_IOVECS) % 8;
            if (self.free_io_vec_idx[byte_index] & (1 << bit_index)) == 0 {
                return Ok(free_idx);
            }
            free_idx += 1;
        }
        return Err(ExhaustedIOVecError("Unable to find a free iovec slot for IOUring to use".to_string()));
    }

    pub fn set_io_vec_in_use(&mut self, idx: usize) {
        let byte_index = idx / 8;
        let bit_index = idx % 8;
        self.free_io_vec_idx[byte_index] |= 1 << bit_index;
    }

    pub fn free_io_vec_in_use(&mut self, idx: usize) {
        let byte_index = idx / 8;
        let bit_index = idx % 8;
        self.free_io_vec_idx[byte_index] &= !(1 << bit_index);
    }

    pub fn get_iovec<'a>(&'a mut self, buf: *const u8, len: usize) -> (&'a iovec, usize) {
        //TODO: Handle error in a good way
        let free_idx = self.get_next_free_iovec_slot().unwrap();
        self.set_io_vec_in_use(free_idx);
        let iovec = &mut self.iovecs[free_idx];
        iovec.iov_base = buf as *mut std::ffi::c_void;
        iovec.iov_len = len;
        (iovec, free_idx)
    }
}

impl IO for LinuxIO {
    fn open_file(&self, path: &str) -> Result<Rc<dyn File>> {
        trace!("open_file(path = {})", path);
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .open(path)?;
        // Let's attempt to enable direct I/O. Not all filesystems support it
        // so ignore any errors.
        let fd = file.as_raw_fd();
        match nix::fcntl::fcntl(fd, FcntlArg::F_SETFL(OFlag::O_DIRECT)) {
            Ok(_) => {},
            Err(error) => debug!("Error {error:?} returned when setting O_DIRECT flag to read file. The performance of the system may be affected"),
        };
        Ok(Rc::new(LinuxFile {
            io: self.inner.clone(),
            file,
        }))
    }

    fn run_once(&self) -> Result<()> {
        trace!("run_once()");
        let mut inner = self.inner.borrow_mut();
        let mut opt_io_vec_idx: Option<usize> = None;
        {
            let ring = &mut inner.ring;
            ring.submit_and_wait(1)?;
            let cq = &mut ring.completion();
            while let Some(cqe) = cq.next() {
                let result = cqe.result();
                ensure!(
                    result >= 0,
                    LinuxIOError::IOUringCQError(result)
                );
                let c = unsafe { Rc::from_raw(cqe.user_data() as *const ReadCompletionWrapped) };
                c.completion.complete();
                opt_io_vec_idx = Some(c.io_vec_idx);
            }
        }
        //TODO: Not a fan at all, this relies too heavily on getting only one entry from ring.
        // Ownership rules does not allow me to have the mutable ring
        match opt_io_vec_idx {
            Some(io_vec_idx) => {
                inner.free_io_vec_in_use(io_vec_idx);
            },
            None => {}
        }

        Ok(())
    }
}

pub struct LinuxFile {
    io: Rc<RefCell<InnerLinuxIO>>,
    file: std::fs::File,
}

impl File for LinuxFile {
    fn pread(&self, pos: usize, c: Rc<Completion>) -> Result<()> {
        trace!("pread(pos = {}, length = {})", pos, c.buf().len());
        let fd = io_uring::types::Fd(self.file.as_raw_fd());
        let mut io = self.io.borrow_mut();

        let read_e = {
            let mut buf = c.buf_mut();
            let len = buf.len();
            let buf = buf.as_mut_ptr();
            let (iovec, io_vec_idx) = io.get_iovec(buf, len);
            let cwrapped = Rc::new(ReadCompletionWrapped {
                completion: c.clone(),
                io_vec_idx: io_vec_idx,
            });
            let ptr = Rc::into_raw(cwrapped.clone());
            io_uring::opcode::Readv::new(fd, iovec, 1)
                .offset(pos as u64)
                .build()
                .user_data(ptr as u64)
        };
        let ring = &mut io.ring;
        unsafe {
            ring.submission()
                .push(&read_e)
                .expect("submission queue is full");
        }
        Ok(())
    }

    fn pwrite(
        &self,
        pos: usize,
        buffer: Rc<RefCell<crate::Buffer>>,
        c: Rc<WriteCompletion>,
    ) -> Result<()> {
        let mut io = self.io.borrow_mut();
        let fd = io_uring::types::Fd(self.file.as_raw_fd());
        let write = {
            let buf = buffer.borrow();
            let (iovec, io_vec_idx) = io.get_iovec(buf.as_ptr(), buf.len());
            let cwrapped = Rc::new(WriteCompletionWrapped {
                completion: c.clone(),
                io_vec_idx: io_vec_idx,
            });
            let ptr = Rc::into_raw(cwrapped.clone());
            io_uring::opcode::Writev::new(fd, iovec, 1)
                .offset(pos as u64)
                .build()
                .user_data(ptr as u64)
        };
        let ring = &mut io.ring;
        unsafe {
            ring.submission()
                .push(&write)
                .expect("submission queue is full");
        }
        Ok(())
    }
}
