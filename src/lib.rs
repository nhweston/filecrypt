use aes_gcm::{Aes128Gcm, AeadInPlace, Key, Nonce};
use aes_gcm::aead::NewAead;
use base64;
use generic_array::typenum::{U12, U16};
use rand::{RngCore, OsRng};
use std::{fs, thread};
use std::fs::{File, OpenOptions};
use std::io::prelude::{Read, Write};
use std::path::Path;
use uuid::Uuid;

pub fn encrypt_file(
    path_in: &Path,
    path_out: &Path,
    chunk_len: usize,
) -> Metadata {
    println!("path_in = {}", path_in.display());
    println!("path_out = {}", path_out.display());
    println!("path in = {}", chunk_len);
    check_chunk_len(chunk_len);
    let mut file = File::open(path_in).unwrap();
    let mut file_len = 0;
    let mut chunks = Vec::new();
    let mut threads = Vec::new();
    fs::create_dir_all(path_out).unwrap();
    loop {
        let mut buffer = Vec::with_capacity(chunk_len);
        let num_bytes = (&mut file).take(chunk_len as u64).read_to_end(&mut buffer).unwrap();
        println!("read {} bytes", num_bytes);
        if num_bytes == 0 {
            break;
        }
        for _ in num_bytes..chunk_len {
            buffer.push(0);
        }
        file_len += num_bytes;
        let (chunk, path) = {
            let chunk = Chunk::random();
            let path = path_out.join(chunk.filename());
            let clone = chunk.clone();
            chunks.push(chunk);
            (clone, path)
        };
        let thread = thread::spawn(move || {
            chunk.encrypt(&mut buffer);
            let mut file = OpenOptions::new().create(true).write(true).open(path).unwrap();
            file.write_all(buffer.as_slice()).unwrap();
        });
        threads.push(thread);
    }
    for thread in threads {
        thread.join().unwrap();
    }
    Metadata::new(file_len, chunk_len, chunks)
}

pub fn encrypt_file_unchunked(
    path_in: &Path,
    path_out: &Path,
) -> Metadata {
    let mut file_in = File::open(path_in).unwrap();
    let mut buffer = Vec::new();
    let file_len = (&mut file_in).read_to_end(&mut buffer).unwrap();
    let chunk = Chunk::random();
    fs::create_dir_all(path_out).unwrap();
    let path = path_out.join(chunk.filename());
    let num_padding_bytes = if file_len % 16 == 0 { 0 } else { 16 - file_len % 16 };
    for _ in 0..num_padding_bytes {
        buffer.push(0);
    }
    let chunk_len = buffer.len() + 16;
    buffer.reserve(chunk_len - buffer.len());
    chunk.encrypt(&mut buffer);
    let mut file_out = OpenOptions::new().create(true).write(true).open(path).unwrap();
    file_out.write_all(buffer.as_slice()).unwrap();
    Metadata {
        file_len,
        chunk_len,
        chunks: vec![chunk],
    }
}

pub fn decrypt_file(
    path_in: &Path,
    path_out: &Path,
    metadata: &Metadata,
) {
    let mut file = OpenOptions::new().create(true).write(true).open(path_out).unwrap();
    let Metadata { file_len, chunk_len, chunks } = metadata;
    let mut threads = Vec::new();
    for chunk in chunks {
        let chunk = chunk.clone();
        let path = path_in.join(chunk.filename());
        let mut buffer = Vec::with_capacity(*chunk_len);
        let thread = thread::spawn(move || {
            let mut file = File::open(path).unwrap();
            file.read_to_end(&mut buffer).unwrap();
            chunk.decrypt(&mut buffer);
            buffer
        });
        threads.push(thread);
    }
    let last_len = {
        let remainder = *file_len % *chunk_len;
        if remainder == 0 { *chunk_len } else { remainder }
    };
    let mut i = 0;
    let last_idx = threads.len() - 1;
    for thread in threads {
        let data = thread.join().unwrap();
        let slice = if i < last_idx { &data[..] } else { &data[..last_len] };
        file.write_all(slice).unwrap();
        i += 1;
    }
}

fn check_chunk_len(chunk_len: usize) {
    assert_eq!(chunk_len % 16, 0, "chunk_len must be a multiple of 16");
}

fn check_num_chunks(file_len: usize, chunk_len: usize, num_keys: usize) {
    let expected = (file_len + chunk_len - 16) / (chunk_len - 16);
    assert_eq!(num_keys, expected, "expected {} chunks, found {}", expected, num_keys);
}

pub struct Metadata {
    file_len: usize,
    chunk_len: usize,
    chunks: Vec<Chunk>,
}

impl Metadata {

    pub fn new(
        file_len: usize,
        chunk_len: usize,
        chunks: Vec<Chunk>,
    ) -> Self {
        check_chunk_len(chunk_len);
        check_num_chunks(file_len, chunk_len, chunks.len());
        Metadata { chunk_len, file_len, chunks }
    }

    pub fn to_string(&self) -> String {
        let mut string = String::new();
        string.push_str(&format!("FILE_LEN {}\n", self.file_len));
        string.push_str(&format!("CHUNK_LEN {}\n", self.chunk_len));
        for i in 0..self.chunks.len() {
            let chunk = &self.chunks[i];
            let key_string = base64::encode(chunk.key.as_slice());
            string.push_str(&format!("CHUNK {}:{}\n", chunk.filename(), key_string));
        }
        string
    }

}

#[derive(Clone)]
pub struct Chunk {
    id: Uuid,
    key: Key<U16>,
}

impl Chunk {

    pub fn new(id: Uuid, key: Key<U16>) -> Self {
        Chunk { id, key }
    }

    pub fn random() -> Self {
        let mut rng = OsRng::new().unwrap();
        let mut random = || {
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes);
            bytes
        };
        let id = {
            let bytes = random();
            Uuid::from_bytes(&bytes).unwrap()
        };
        let key = Key::from(random());
        Self { id, key }
    }

    pub fn filename(&self) -> String {
        let mut result = self.id.simple().to_string();
        result.make_ascii_lowercase();
        result
    }

    pub fn nonce(&self) -> Nonce<U12> {
        let bytes = &self.key.as_slice()[..12];
        *Nonce::from_slice(bytes)
    }

    pub fn encrypt(&self, buffer: &mut Vec<u8>) {
        let cipher = Aes128Gcm::new(&self.key);
        buffer.reserve(16);
        cipher.encrypt_in_place(&self.nonce(), &[], buffer).unwrap();
    }

    pub fn decrypt(&self, buffer: &mut Vec<u8>) {
        let cipher = Aes128Gcm::new(&self.key);
        cipher.decrypt_in_place(&self.nonce(), &[], buffer).unwrap();
    }

}
