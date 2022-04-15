use aes_gcm::{Aes128Gcm, AeadInPlace, Key, Nonce};
use aes_gcm::aead::NewAead;
use base64;
use generic_array::typenum::{U12, U16};
use rand::{RngCore, OsRng};
use serde::{Deserialize, Serialize};
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
    check_chunk_len(chunk_len);
    let mut file = File::open(path_in).unwrap();
    let mut file_len = 0;
    let mut chunks = Vec::new();
    let mut threads = Vec::new();
    fs::create_dir_all(path_out).unwrap();
    loop {
        let mut buffer = Vec::with_capacity(chunk_len);
        let num_bytes = (&mut file).take(chunk_len as u64).read_to_end(&mut buffer).unwrap();
        if num_bytes == 0 {
            break;
        }
        for _ in num_bytes..chunk_len {
            buffer.push(0);
        }
        file_len += num_bytes;
        let (chunk, path) = {
            let chunk = Chunk::random();
            let path = path_out.join(chunk.id_string());
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
    Metadata { file_len, chunk_len, chunks }
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
    let path = path_out.join(chunk.id_string());
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
    let Metadata { file_len, chunk_len, chunks } = metadata;
    check_chunk_len(*chunk_len);
    check_num_chunks(*file_len, *chunk_len, chunks.len());
    let mut file = OpenOptions::new().create(true).write(true).open(path_out).unwrap();
    let mut threads = Vec::new();
    for chunk in chunks {
        let chunk = chunk.clone();
        let path = path_in.join(chunk.id_string());
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

fn check_num_chunks(file_len: usize, chunk_len: usize, num_chunks: usize) {
    let expected = (file_len + chunk_len - 16) / (chunk_len - 16);
    assert_eq!(num_chunks, expected, "expected {} chunks, found {}", expected, num_chunks);
}

#[derive(Deserialize, Serialize)]
pub struct Metadata {
    file_len: usize,
    chunk_len: usize,
    chunks: Vec<Chunk>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(into = "ChunkIntermediate", try_from = "ChunkIntermediate")]
pub struct Chunk {
    id: Uuid,
    key: Key<U16>,
}

impl Chunk {

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

    pub fn id_string(&self) -> String {
        let mut result = self.id.simple().to_string();
        result.make_ascii_lowercase();
        result
    }

    pub fn key_string(&self) -> String {
        base64::encode(self.key.as_slice()).to_string()
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

#[derive(Deserialize, Serialize)]
struct ChunkIntermediate {
    id: String,
    key: String,
}

impl From<Chunk> for ChunkIntermediate {

    fn from(chunk: Chunk) -> Self {
        ChunkIntermediate {
            id: chunk.id_string(),
            key: chunk.key_string(),
        }
    }

}

impl TryFrom<ChunkIntermediate> for Chunk {

    type Error = &'static str;

    fn try_from(intermediate: ChunkIntermediate) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&intermediate.id).map_err(|_| "malformed ID")?;
        let key = {
            let bytes = base64::decode(&intermediate.key).map_err(|_| "malformed key")?;
            *Key::from_slice(&bytes)
        };
        Ok(Chunk { id, key })
    }

}
