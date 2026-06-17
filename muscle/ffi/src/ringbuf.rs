use crate::PacketContext;

/// Lock-free SPSC ring buffer. Single producer (Rust), single consumer (Go via FFI).
pub struct RingBuf {
    buf: Vec<Option<PacketContext>>,
    head: usize, // write position
    tail: usize, // read position
    cap: usize,
}

impl RingBuf {
    pub fn new(cap: usize) -> Self {
        let mut buf = Vec::with_capacity(cap);
        buf.resize_with(cap, || None);
        RingBuf { buf, head: 0, tail: 0, cap }
    }

    pub fn push(&mut self, pkt: PacketContext) -> bool {
        let next = (self.head + 1) % self.cap;
        if next == self.tail {
            return false; // full
        }
        self.buf[self.head] = Some(pkt);
        self.head = next;
        true
    }

    pub fn pop(&mut self) -> Option<PacketContext> {
        if self.head == self.tail {
            return None; // empty
        }
        let pkt = self.buf[self.tail].take();
        self.tail = (self.tail + 1) % self.cap;
        pkt
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            self.cap - self.tail + self.head
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pkt() -> PacketContext {
        PacketContext {
            timestamp: 0, src_ip: [0; 16], dst_ip: [0; 16],
            src_port: 0, dst_port: 0, protocol: [0; 8], tcp_flags: [0; 8],
            payload_size: 0, payload_hash: 0, direction: [0; 8], _pad: [0; 6],
        }
    }

    #[test]
    fn test_push_pop() {
        let mut rb = RingBuf::new(4);
        assert!(rb.push(test_pkt()));
        assert!(rb.push(test_pkt()));
        assert_eq!(rb.len(), 2);
        assert!(rb.pop().is_some());
        assert!(rb.pop().is_some());
        assert!(rb.pop().is_none());
    }

    #[test]
    fn test_full() {
        let mut rb = RingBuf::new(4); // cap 4 means 3 usable slots
        assert!(rb.push(test_pkt()));
        assert!(rb.push(test_pkt()));
        assert!(rb.push(test_pkt()));
        assert!(!rb.push(test_pkt())); // 4th should fail
    }

    #[test]
    fn test_wraparound() {
        let mut rb = RingBuf::new(4);
        rb.push(test_pkt()); rb.push(test_pkt()); rb.push(test_pkt());
        rb.pop(); // remove one
        assert!(rb.push(test_pkt())); // should succeed after pop
        assert_eq!(rb.len(), 3);
    }
}
