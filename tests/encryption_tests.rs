//! Test RC4 implementation on test vectors from
//! Wikipedia: https://en.wikipedia.org/wiki/RC4#Test_vectors

use rc4_rs;

#[test]
fn encrypt_key_plaintext() {
    let mut rc4 = rc4_rs::RC4::new("Key".as_bytes());

    let mut data = Vec::from("Plaintext");
    rc4.xor_keystream_with(&mut data);

    let ciphertext = [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3];
    assert_eq!(data.as_slice(), ciphertext);
}

#[test]
fn encrypt_wiki_pedia() {
    let mut rc4 = rc4_rs::RC4::new("Wiki".as_bytes());

    let mut data = Vec::from("pedia");
    rc4.xor_keystream_with(&mut data);

    let ciphertext = [0x10, 0x21, 0xBF, 0x04, 0x20];
    assert_eq!(data.as_slice(), ciphertext);
}

#[test]
fn encrypt_secret_attack_at_dawn() {
    let mut rc4 = rc4_rs::RC4::new("Secret".as_bytes());

    let mut data = Vec::from("Attack at dawn");
    rc4.xor_keystream_with(&mut data);

    let ciphertext = [
        0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5,
    ];
    assert_eq!(data.as_slice(), ciphertext);
}
