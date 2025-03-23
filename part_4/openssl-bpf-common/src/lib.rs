#![no_std]


pub struct SSLData {
    pub buf: [u8; 200],
    pub num_bytes: usize
}