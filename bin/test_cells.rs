use std::{
    alloc::{GlobalAlloc, System, Layout}, sync::{Arc, atomic::{AtomicU64, Ordering}}, 
    thread, time::Duration
};

struct TracingAllocator {
    allocated: AtomicU64,
}

unsafe impl GlobalAlloc for TracingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        self.allocated.fetch_add(layout.size() as u64, Ordering::Relaxed);
        ret
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc_zeroed(layout);
        self.allocated.fetch_add(layout.size() as u64, Ordering::Relaxed);
        ret
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ret = System.realloc(ptr, layout, new_size);
        self.allocated.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        self.allocated.fetch_add(new_size as u64, Ordering::Relaxed);
        ret
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.allocated.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static GLOBAL: TracingAllocator = TracingAllocator { 
    allocated: AtomicU64::new(0),
};

fn main() {

    thread::spawn(
        || {
            let mut prev = 0;
            loop {
                thread::sleep(Duration::from_millis(5000));
                let allocated = GLOBAL.allocated.load(Ordering::Relaxed);
                if allocated != prev {
                    println!("Allocated {} MB", allocated / (1024 * 1024));
                    prev = allocated;
                }
            }
        }
    );

    //let mut file = std::fs::File::open("/Users/kirill/block_boc_10c81295f43b9d0398280901bf8c35892dad75a4147c904f021ab2e0b9f910e0.boc").unwrap();
    let mut file = std::fs::File::open("/Users/kirill/8639025df772755c57fd01d9cb7d03ca4095b95fa1fcb7ec42e1b8513ab9.boc").unwrap();

    //let now = std::time::Instant::now();
    // let data = std::fs::read("/Users/kirill/8639025df772755c57fd01d9cb7d03ca4095b95fa1fcb7ec42e1b8513ab9.boc").unwrap();
    //let data = std::fs::read("/Users/kirill/block_boc_10c81295f43b9d0398280901bf8c35892dad75a4147c904f021ab2e0b9f910e0.boc").unwrap();
    //println!("read {}bytes {}ms", data.len(), now.elapsed().as_millis());

    let now = std::time::Instant::now();
    println!("now 0 {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
    
    let root = ton_types::cells_serialization::deserialize_tree_of_cells(&mut file).unwrap();
    //let root = ton_types::cells_serialization::deserialize_tree_of_cells_inmem(data).unwrap();
    
    // assert_eq!(
    //     format!("{:x}", root.repr_hash()), 
    //     "10c81295f43b9d0398280901bf8c35892dad75a4147c904f021ab2e0b9f910e0".to_string()
    // );

    println!("now 7 {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());  
    println!("deserialize_tree_of_cells {}ms", now.elapsed().as_millis());

    let allocated = GLOBAL.allocated.load(Ordering::Relaxed);
    println!("DONE Allocated {} MB", allocated / (1024 * 1024));
    // println!("cell_count {} finalization_nanos {}", ton_types::Cell::cell_count(), ton_types::Cell::finalization_nanos());

    thread::sleep(Duration::from_millis(5000));

    // println!("{:x}", root.repr_hash());
    //return;
    println!("serialize_toc");

    let now = std::time::Instant::now();
    let v = ton_types::serialize_toc(&root).unwrap();
    println!("now 17 {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());   
    println!("serialize_toc {}ms", now.elapsed().as_millis());

    thread::sleep(Duration::from_millis(5000));

    let now = std::time::Instant::now();
    println!("now 0 {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
    
    //let root = ton_types::cells_serialization::deserialize_tree_of_cells(&mut file).unwrap();
    let root2 = ton_types::cells_serialization::deserialize_tree_of_cells_inmem(Arc::new(v)).unwrap();
    
    println!("now 7 {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());    
    println!("deserialize_tree_of_cells {}ms", now.elapsed().as_millis());

    assert_eq!(root.repr_hash(), root2.repr_hash());

}
