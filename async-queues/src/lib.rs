extern crate fortanix_sgx_abi;

use std::{iter, mem, ptr, slice};
use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use fortanix_sgx_abi::{FifoDescriptor, Slot};

//#[derive(Clone)]
//pub struct Sender<T>(Arc<Queue<T>>);
//
//unsafe impl<T> Send for Sender<T> {}
//
//impl<T: Copy + Sync> Sender<T> {
//    pub fn send(&self, id: usize, data: T) -> Option<bool /* wakeup reciever? */> {
//        unsafe { (self.0).0.send(id, data) }
//    }
//
//    pub fn into_raw(self) -> FifoDescriptor<T> {
//        self.0.into_raw()
//    }
//}
//
//unsafe impl<T> Send for Reciever<T> {}
//
//pub struct Reciever<T>(Arc<Queue<T>>);
//
//impl<T: Copy> Reciever<T> {
//    pub fn recv(&mut self) -> Option<(usize, T, bool /* wakeup sender? */)> {
//        unsafe { (self.0).0.recv() }
//    }
//
//    pub fn is_empty(&self) -> bool {
//        unsafe { (self.0).0.len() == 0 }
//    }
//
//    pub fn into_raw(self) -> FifoDescriptor<T> {
//        self.0.into_raw()
//    }
//}
//
//struct Queue<T>(FifoDescriptorContainer<T>);
//
//impl<T> Queue<T> {
//    pub fn new(capacity: usize) -> Self {
//        let offsets: Box<AtomicUsize> = Box::new(AtomicUsize::new(0));
//        let data: Box<[Slot<T>]> = iter::repeat_with(|| unsafe { mem::zeroed() }).take(capacity).collect::<Vec<_>>()
//            .into_boxed_slice();
//        assert_eq!(data.len(), capacity);
//        let data = Box::into_raw(data) as *mut Slot<T>;
//        let descriptor = FifoDescriptor { data, capacity: capacity as u32, offsets: Box::into_raw(offsets) };
////        let descriptor = FifoDescriptorContainer::from_raw(data, capacity as u32, Box::into_raw(offsets));
//        Queue(descriptor)
//    }
//
//    fn into_raw(&self) -> FifoDescriptor<T> {
//        unsafe { ptr::read(&self.0) }
//    }
//}
//
//impl<T> Drop for Queue<T> {
//    fn drop(&mut self) {
//        unsafe { Box::from_raw(self.0.offsets as *mut AtomicUsize) };
//        unsafe { Box::from_raw(slice::from_raw_parts_mut(self.0.data as *mut Slot<T>, self.0.capacity as usize)) };
//    }
//}
//
//pub fn channel<T>(capacity: usize) -> (Sender<T>, Reciever<T>) {
//    let queue = Arc::new(Queue::new(capacity));
//    (Sender(queue.clone()), Reciever(queue))
//}

/*
/// A circular buffer used as a FIFO queue with atomic reads and writes.
///
/// The read offset is the element that was most recently read by the
/// receiving end of the queue. The write offset is the element that was
/// most recently written by the sending end. If the two offsets are equal,
/// the queue is either empty or full.
///
/// The size of the buffer is such that not all the bits of the offset are
/// necessary to encode the current offset. The next highest unused bit is
/// used to keep track of the number of times the offset has wrapped
/// around. If the offsets are the same and the bit is the same in the read
/// and write offsets, the queue is empty. If the bit is different in the
/// read and write offsets, the queue is full.
///
/// The following procedures will operate the queues in a multiple producer
/// single consumer (MPSC) fashion.
#[repr(C)]
pub struct FifoDescriptor<T> {
    /// Pointer to the queue memory. Must have a size of
    /// `capacity * size_of::<Slot<T>>()` bytes and have alignment `align_of::<Slot<T>>()`.
    pub data: *const Slot<T>,
    /// The number of elements pointed to by `data`. Must be a power of two
    /// less than or equal to 2³⁰.
    pub capacity: u32,
    /// Actually a `(u32, u32)` tuple, aligned to allow atomic operations
    /// on both halves simultaneously. The first element (low dword) is
    /// the read offset and the second element (high dword) is the write
    /// offset.
    pub offsets: *const AtomicUsize,
}

unsafe impl<T: Send> Send for FifoDescriptor<T> {}
unsafe impl<T: Send> Sync for FifoDescriptor<T> {}

#[repr(C)]
pub struct Slot<T> {
    /// `0` indicates this slot is empty.
    id: AtomicUsize,
    data: UnsafeCell<T>,
}*/

pub struct FifoDescriptorContainer<T> {
    pub inner: FifoDescriptor<T>,
}

#[derive(Debug)]
struct Offsets {
    read: u32,
    write: u32,
    read_blocked: bool,
}

impl Offsets {
    fn as_usize(&self) -> usize {
        ((self.write as usize) << 32) | (if self.read_blocked { 1 << 31 } else { 0 }) | (self.read as usize)
    }

    fn from_usize(offsets: usize) -> Self {
        Offsets {
            write: (offsets >> 32) as u32,
            read_blocked: offsets & (1 << 31) != 0,
            read: (offsets & ((1 << 31) - 1)) as u32,
        }
    }

    fn is_empty(&self) -> bool {
        self.read == self.write
    }

    fn is_full(&self, capacity: u32) -> bool {
        self.read | capacity == self.write | capacity && !self.is_empty()
    }

    fn read_offset(&self, capacity: u32) -> isize {
        (self.read & (capacity - 1)) as isize
    }

    fn write_offset(&self, capacity: u32) -> isize {
        (self.write & (capacity - 1)) as isize
    }

    fn increment_read_offset(&mut self, capacity: u32) {
        self.read = (self.read + 1) & ((capacity << 1) - 1);
    }

    fn increment_write_offset(&mut self, capacity: u32) {
        self.write = (self.write + 1) & ((capacity << 1) - 1);
        self.read_blocked = false;
    }

    fn len(&self, capacity: u32) -> usize {
        ((if self.read <= self.write { 0 } else { 2 * capacity }) + self.write - self.read) as usize
    }
}

impl<T: Copy> FifoDescriptorContainer<T> {
    pub fn new(capacity: usize) -> Self {
        let offsets: Box<AtomicUsize> = Box::new(AtomicUsize::new(0));
        let data: Box<[Slot<T>]> = iter::repeat_with(|| unsafe { mem::zeroed() }).take(capacity).collect::<Vec<_>>()
            .into_boxed_slice();
        assert_eq!(data.len(), capacity);
        let data = Box::into_raw(data) as *mut Slot<T>;
        //let descriptor = FifoDescriptor { data, capacity: capacity as u32, offsets: Box::into_raw(offsets) };
        Self::from_raw(data, capacity, Box::into_raw(offsets))
    }

    pub fn from_raw(data: *mut Slot<T>, capacity: usize, offsets: *mut AtomicUsize) -> Self {
        FifoDescriptorContainer {
            inner: FifoDescriptor { data, capacity: capacity as u32, offsets }
        }
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity as usize
    }

    pub unsafe fn len(&self) -> usize {
        Offsets::from_usize((*self.inner.offsets).load(Ordering::Relaxed)).len(self.inner.capacity)
    }

    pub unsafe fn send(&self, id: usize, data: T) -> Option<bool /* wakeup reader? */> {
        let (mut old_offsets, mut offsets);
        loop {
            // 1. Load the current offsets.
            old_offsets = (*self.inner.offsets).load(Ordering::Acquire);
            offsets = Offsets::from_usize(old_offsets);

            // 2. If the queue is full, wait, then go to step 1.
            if offsets.is_full(self.inner.capacity) {
                return None
            }

            // 3. Add 1 to the write offset and do an atomic compare-and-swap (CAS)
            //    with the current offsets. If the CAS was not succesful, go to step 1.
            offsets.increment_write_offset(self.inner.capacity);
            if (*self.inner.offsets).compare_and_swap(old_offsets, offsets.as_usize(), Ordering::Acquire) == old_offsets {
                break
            }
        }

        let offset = offsets.write_offset(self.inner.capacity);
        assert!(offset < self.inner.capacity as isize);
        let slot = &*self.inner.data.offset(offset);
        // 4. Write the data, then the `id`.
        *slot.data.get() = data;
        // Use `Ordering::Release` so that everyone sees the above write to `data` before the non-zero `id`.
        slot.id.store(id, Ordering::Release);

        Some(Offsets::from_usize(old_offsets).read_blocked)
    }

    pub unsafe fn recv(&self) -> Option<(usize, T, bool /* wakeup writer? */)> {
        // 1. Load the current offsets.
        let mut old_offsets = (*self.inner.offsets).load(Ordering::Acquire);

        // 2. If the queue is empty, set `read_blocked` and wait
        let mut offsets;
        while { offsets = Offsets::from_usize(old_offsets); offsets.is_empty() } {
            if offsets.read_blocked {
                return None
            }
            old_offsets = (*self.inner.offsets).fetch_or(1 << 31, Ordering::Release); // set `read_blocked`
        }

        // Unset `read_blocked` in case the above loop set `read_blocked` right after something was sent.
        if offsets.read_blocked {
            (*self.inner.offsets).fetch_and(!(1 << 31), Ordering::Relaxed);
        }

        // 3. Add 1 to the read offset.
        offsets.increment_read_offset(self.inner.capacity);

        // 4. Read the `id` at the new read offset.
        // 5. If `id` is `0`, go to step 4 (spin). Spinning is OK because data is
        //    expected to be written imminently.
        // 6. Store `0` in the `id` and read the data.
        let offset = offsets.read_offset(self.inner.capacity);
        assert!(offset < self.inner.capacity as isize);
        let slot = &*self.inner.data.offset(offset);
        let id = iter::repeat_with(|| slot.id.load(Ordering::Acquire)).find(|&id| id != 0).unwrap();
        slot.id.store(0, Ordering::Relaxed);
        let data = *slot.data.get();

        // 7. Store the new read offset.
        if offsets.read == 0 {
            (*self.inner.offsets).fetch_sub(((self.inner.capacity << 1) - 1) as usize, Ordering::Release);
        } else {
            (*self.inner.offsets).fetch_add(1, Ordering::Release);
        }

        // 8. If the queue was full in step 1, signal the writer to wake up.
        Some((id, data, Offsets::from_usize(old_offsets).is_full(self.inner.capacity)))
    }
}
