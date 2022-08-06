use anyhow::anyhow;
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use zeroize::Zeroize;

// Build argon2 config
fn argon2_config<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}

pub fn decrypt_file(
    enc_file_path: &str,
    dst_file_path: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];

    // Open the encrypted file and create a new dst file
    let mut encrypted_file = File::open(enc_file_path)?;

    // Read the salt at the beginning of the encrypted file
    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    // Read the nonce at the beginning of the encrypted file
    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = argon2_config();

    // Get the key from the password and nonce
    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let ad = [0u8; 32];

    let mut file_data = fs::read(enc_file_path)?;

    // Get only the last 44 elements of file_data (skip salt and nonce)
    file_data = file_data[44..].to_vec();

    let ring_key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key).unwrap(),
    );
    let ring_nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
    let ring_ad = ring::aead::Aad::from(&ad);
    let plaintext = ring_key
        .open_in_place(ring_nonce, ring_ad, &mut file_data)
        .map_err(|err| anyhow!("ring: decrypting file: {}", err))?;

    fs::write(&dst_file_path, plaintext)?;

    // Securely clear secrets from memory
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

pub fn encrypt_file(
    src_file_path: &str,
    dst_file_path: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    let argon2_config = argon2_config();

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];

    // Fill salt and nonce arrays with random bytes
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // Hash the password with argon2id algorithm
    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let ad = [0u8; 32];

    let mut file_data = fs::read(src_file_path)?;

    let ring_key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key).unwrap(),
    );
    let ring_nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
    let ring_ad = ring::aead::Aad::from(&ad);
    ring_key
        .seal_in_place_append_tag(ring_nonce, ring_ad, &mut file_data)
        .map_err(|err| anyhow!("ring: encrypting file: {}", err))?;

    // Create the dst file
    let mut dst_file = File::create(dst_file_path)?;

    // Write salt and nonce at the beginning of the dst file
    dst_file.write(&salt)?;
    dst_file.write(&nonce)?;
    dst_file.write(&file_data)?;

    // Securely clear secrets from memory
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}
