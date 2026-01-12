use core::{
    borrow::Borrow,
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
};

use aya_ebpf_bindings::helpers::{bpf_ringbuf_output, bpf_ringbuf_query, bpf_ringbuf_reserve};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_RINGBUF,
    btf_maps,
    maps::ring_buf::{RingBufBytes, RingBufEntry},
};

#[repr(transparent)]
pub struct RingBuf<T, const M: usize, const F: usize = 0>(UnsafeCell<RingBufDef<T, M, F>>);

#[expect(
    dead_code,
    reason = "These fields exist only for BTF metadata exposure. None of them are actually used."
)]
pub struct RingBufDef<V, const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_RINGBUF as usize],
    value: *const V,
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: btf_maps::AyaBtfMapMarker,
}

#[expect(
    clippy::new_without_default,
    reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
)]
impl<V, const M: usize, const F: usize> RingBufDef<V, M, F> {
    pub const fn new() -> Self {
        Self {
            r#type: ::core::ptr::null(),
            value: ::core::ptr::null(),
            max_entries: ::core::ptr::null(),
            map_flags: ::core::ptr::null(),
            _anon: btf_maps::AyaBtfMapMarker::new(),
        }
    }
}

unsafe impl<V: Sync, const M: usize, const F: usize> Sync for RingBuf<V, M, F> {}

impl<V, const M: usize, const F: usize> RingBuf<V, M, F> {
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(RingBufDef::new()))
    }

    /// Reserve a dynamically sized byte buffer in the ring buffer.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// Note that using this method requires care; the verifier does not allow truly dynamic
    /// allocation sizes. In other words, it is incumbent upon users of this function to convince
    /// the verifier that `size` is a compile-time constant. Good luck!
    pub fn reserve_bytes(&self, size: usize, flags: u64) -> Option<RingBufBytes<'_>> {
        let ptr =
            unsafe { bpf_ringbuf_reserve(self.0.get().cast(), size as u64, flags) }.cast::<u8>();
        (!ptr.is_null()).then(|| {
            let inner = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
            RingBufBytes::new(inner)
        })
    }

    /// Reserve memory in the ring buffer that can fit `V`.
    ///
    /// Returns `None` if the ring buffer is full.
    #[cfg(generic_const_exprs)]
    pub fn reserve(&self, flags: u64) -> Option<RingBufEntry<V>>
    where
        Assert<{ 8 % mem::align_of::<T>() == 0 }>: IsTrue,
    {
        self.reserve_impl(flags)
    }

    /// Reserve memory in the ring buffer that can fit `V`.
    ///
    /// Returns `None` if the ring buffer is full.
    ///
    /// The kernel will reserve memory at an 8-bytes aligned boundary, so `mem::align_of<T>()` must
    /// be equal or smaller than 8. If you use this with a `T` that isn't properly aligned, this
    /// function will be compiled to a panic; depending on your panic_handler, this may make
    /// the eBPF program fail to load, or it may make it have undefined behavior.
    pub fn reserve(&self, flags: u64) -> Option<RingBufEntry<V>> {
        assert_eq!(8 % mem::align_of::<V>(), 0);
        self.reserve_impl(flags)
    }

    fn reserve_impl(&self, flags: u64) -> Option<RingBufEntry<V>> {
        let ptr =
            unsafe { bpf_ringbuf_reserve(self.0.get().cast(), mem::size_of::<V>() as u64, flags) }
                .cast::<MaybeUninit<V>>();
        unsafe { ptr.as_mut() }.map(|ptr| RingBufEntry::new(ptr))
    }

    /// Copy `data` to the ring buffer output.
    ///
    /// Consider using [`reserve`] and [`submit`] if `V` is statically sized and you want to save a
    /// copy from either a map buffer or the stack.
    ///
    /// Unlike [`reserve`], this function can handle dynamically sized types (which is hard to
    /// create in eBPF but still possible, e.g. by slicing an array).
    ///
    /// Note: `V` must be aligned to no more than 8 bytes; it's not possible to fulfill larger
    /// alignment requests. If you use this with a `V` that isn't properly aligned, this function will
    /// be compiled to a panic and silently make your eBPF program fail to load.
    /// See [here](https://github.com/torvalds/linux/blob/3f01e9fed/kernel/bpf/ringbuf.c#L418).
    ///
    /// [`reserve`]: RingBuf::reserve
    /// [`submit`]: RingBufEntry::submit
    pub fn output(&self, data: impl Borrow<V>, flags: u64) -> Result<(), i64> {
        let data = data.borrow();
        assert_eq!(8 % mem::align_of_val(data), 0);
        let ret = unsafe {
            bpf_ringbuf_output(
                self.0.get().cast(),
                core::ptr::from_ref(data).cast_mut().cast(),
                mem::size_of_val(data) as u64,
                flags,
            )
        };
        if ret < 0 { Err(ret) } else { Ok(()) }
    }

    /// Query various information about the ring buffer.
    ///
    /// Consult `bpf_ringbuf_query` documentation for a list of allowed flags.
    pub fn query(&self, flags: u64) -> u64 {
        unsafe { bpf_ringbuf_query(self.0.get().cast(), flags) }
    }
}
