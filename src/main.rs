#[repr(transparent)] 
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd,Ord)] 
struct Perm(u8); 
 
#[repr(transparent)] 
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd,Ord)] 
struct VirtAddr(usize); 

const PERM_READ: u8 = 1 << 1; 
const PERM_WRITE: u8 = 1 << 2;
const PERM_EXEC: u8 = 1 << 3;
const PERM_RAW: u8 = 1 << 4;

/// Block size used for resetting and tracking memory which has been modified
/// The larger this is, the fewer but more expensive memcpys() need to occur,
/// the small, the greater but less expensive memcpys() need to occur.
/// It seems the sweet spot is often 128-4096 bytes
const DIRTY_BLOCK_SIZE: usize = 128;

/// Memory space 
struct Mmu {
    memory:     Vec<u8>,
    permissions: Vec<Perm>, 
    cur_alc: VirtAddr,

    // Trach `block` in memory which are dirty 
    dirty:Vec<usize>, 

    // Track which part of memory have been dirt 
    dirty_bitmap: Vec<u64> 
}

impl Mmu{
    pub fn new(size: usize) -> Self {
        Mmu {
            memory :         vec![0; size],
            permissions :    vec![Perm(0); size],
            cur_alc:         VirtAddr(0x10000), 
            dirty :          Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1), 
            dirty_bitmap :   vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
        }
    } 

    pub fn fork(&self) -> Self {
        let size = self.memory.len(); 
        Mmu {
            memory:         self.memory.clone(), 
            permissions :   self.permissions.clone(), 
            cur_alc:        self.cur_alc.clone(), 
            dirty :          Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1), 
            dirty_bitmap :   vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
        } 
    } 

    /// Restore memory from prior state 
    pub fn reset(&mut self, prior_state: &Mmu){
        for &block in &self.dirty {
            let start = block * DIRTY_BLOCK_SIZE; 
            let end = (block + 1) * DIRTY_BLOCK_SIZE; 

            self.dirty_bitmap[block / 64] = 0; 

            // Recovery memory from prior state 
            self.memory[start..end].copy_from_slice(&prior_state.memory[start..end]);
            
            // Recovery permissions from prior state 
            self.permissions[start..end].copy_from_slice(&prior_state.permissions[start..end]); 
        }
        self.dirty.clear();
    }

    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        let align_size = (size + 0xf) & !0xf;

        // Get the current allocation base address 
        let base = self.cur_alc;  

        if base.0 > self.memory.len() {
            return None;     
        }
        
        
        self.cur_alc = VirtAddr(self.cur_alc.0.checked_add(align_size)?);  
        if self.cur_alc.0 > self.memory.len() {
            return None;
        }

        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));
        Some(base)
    }

    pub fn set_permissions(&mut self, addr:VirtAddr, size: usize, 
                            perm: Perm) -> Option<()> {
        // Apply permissions 
        self.permissions.get_mut(addr.0..addr.0.checked_add(size)?)?
            .iter_mut().for_each(|x| *x = perm);

        Some(())
    }
    
    // write from buf to addr 
    pub fn write_from(&mut self, addr: VirtAddr, buf : &[u8]) -> Option<()> {
        // Check permissions 
        let perms = self.permissions.get_mut(addr.0..addr.0.checked_add(buf.len())?)?; 
        let mut has_raw = false; 
        
        if !perms.iter().all(|x| {
            has_raw |= (x.0 & PERM_RAW) != 0;
            (x.0 & PERM_WRITE) != 0
        }) {
            println!("Doesn't have write permissions!"); 
            return None; 
        } 
        
        self.memory.get_mut(addr.0..addr.0.checked_add(buf.len())?)?
            .copy_from_slice(buf); 
        
        // Change PERM_READ after in-itialized 
        if has_raw {
            perms.iter_mut().for_each(|x| *x = Perm(x.0 | PERM_READ));
        }
        
        /// Put dirty block in dirty-list if not
        /// Change dirty-bitmap if not dirty 
        let block_start = addr.0 / DIRTY_BLOCK_SIZE;
        let block_end = (addr.0 + buf.len()) / DIRTY_BLOCK_SIZE; 
        for block in block_start..=block_end {
            let idx = block_start / 64; 
            let bit = block_start % 64; 
            
            // If not dirty 
            if (self.dirty_bitmap[idx] & (1 << bit)) == 0 {
                // Block is not dirty, push it into dirty list 
                self.dirty.push(block);

                // Change dirty bitmap 
                self.dirty_bitmap[idx] |= 1 << bit; 
            }
        }

        Some(()) 
    }

    // read from addr to buf 
    pub fn read_into(&mut self, addr: VirtAddr, buf: &mut [u8], size: usize) -> Option<()> {
        // Check read permissions 
        let perms = self.permissions.get_mut(addr.0..addr.0.checked_add(size)?)?; 
        if !perms.iter().all(|x| (x.0 & PERM_READ) != 0) {
            println!("Doesn't have read permissions!");
            return None; 
        }

        buf.copy_from_slice(
            self.memory.get(addr.0..addr.0.checked_add(size)?)?
        );

        Some(())
    }
}

/// All state of emulator 
struct Emulator {
    /// Memory for emulator 
    pub memory:Mmu,
}

impl Emulator {
    pub fn new(size: usize) -> Self {
        Emulator {
            memory:Mmu::new(size)
        }
    } 

    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(), 
        }
    }
}

fn main() {
    let mut emu = Emulator::new(1024 * 1024); 
    let base = emu.memory.allocate(4).unwrap(); 
    let mut bytes = [0u8; 4]; 
    {
        let mut forked = emu.fork(); 
        for ii in 0..100_000_000 {
            forked.memory.reset(&emu.memory); 
        }    
    }

}
