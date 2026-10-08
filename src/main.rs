use blake2::{digest::{Update, VariableOutput}, Blake2bVar};
use ed25519_bip32::{DerivationScheme as Scheme, XPrv as EdXPrv};
use bech32::{self, ToBase32, Variant};
use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use midnight_base_crypto::signatures::SigningKey;
use midnight_coin_structure::coin::UserAddress;
use midnight_ledger::dust::{DustPublicKey, DustSecretKey};
use midnight_serialize::Serializable;
use midnight_zswap::keys::{SecretKeys, Seed};
use std::io::{self, Write};
use std::str::FromStr;

// (label, Cardano network id: mainnet=1, everything else=0)
const NETWORKS: [(&str, u8); 3] = [("mainnet", 1), ("preprod", 0), ("testnet", 0)];

fn b32m(hrp: &str, data: &[u8]) -> String {
    bech32::encode(hrp, data.to_base32(), Variant::Bech32m).expect("Bech32m encode failed")
}

// Mainnet has no suffix; every other network appends _{network_id}
fn hrp(base: &str, net: &str) -> String {
    if net == "mainnet" { base.to_string() } else { format!("{base}_{net}") }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Invalid hex at {i}: {e}")))
        .collect()
}

fn prompt(msg: &str) -> String {
    print!("{msg}");
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim_end_matches(['\r', '\n']).to_string()
}

// BIP-32 (secp256k1): m/44'/2400'/0'/{role}/0   Roles: Night=0, Dust=2, Zswap=3
fn derive_role_key(seed: &[u8], role: u32) -> [u8; 32] {
    let path = DerivationPath::from_str(&format!("m/44'/2400'/0'/{role}/0")).expect("bad path");
    let xprv = XPrv::derive_from_path(seed, &path).expect("derivation failed");
    xprv.private_key().to_bytes().into()
}

fn hash224(data: &[u8]) -> [u8; 28] {
    let mut h = Blake2bVar::new(28).unwrap();
    h.update(data);
    let mut out = [0u8; 28];
    h.finalize_variable(&mut out).unwrap();
    out
}

fn cardano_addresses(entropy: &[u8], passphrase: &str, net_id: u8) -> (String, String) {
    // Icarus master key: PBKDF2-HMAC-SHA512(password = passphrase, salt = entropy, 4096 iters, 96 bytes)
    let mut master = [0u8; 96];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(passphrase.as_bytes(), entropy, 4096, &mut master);
    let root = EdXPrv::normalize_bytes_force3rd(master);

    // CIP-1852: m/1852'/1815'/0'
    let h = |i: u32| i | 0x8000_0000;
    let account = root
        .derive(Scheme::V2, h(1852))
        .derive(Scheme::V2, h(1815))
        .derive(Scheme::V2, h(0));

    // payment = 0/0, stake = 2/0
    let key_hash = |chain: u32| {
        let k = account.derive(Scheme::V2, chain).derive(Scheme::V2, 0);
        hash224(&k.public().public_key())
    };
    let pay = key_hash(0);
    let stake = key_hash(2);

    // Base address: header byte 0x0N (type 0, network N) ++ payment hash ++ stake hash
    let mut base = vec![net_id];
    base.extend_from_slice(&pay);
    base.extend_from_slice(&stake);

    // Reward address: header 0xEN ++ stake hash
    let mut reward = vec![0xE0 | net_id];
    reward.extend_from_slice(&stake);

    let (addr_hrp, stake_hrp) = if net_id == 1 { ("addr", "stake") } else { ("addr_test", "stake_test") };
    let enc = |hrp: &str, d: &[u8]| bech32::encode(hrp, d.to_base32(), Variant::Bech32).expect("bech32");
    (enc(addr_hrp, &base), enc(stake_hrp, &reward))
}

fn main() {
    let input = prompt("Enter seed phrase or hex seed: ");
    let input = input.trim();

    // (64-byte BIP-39 seed, optional entropy + passphrase for Cardano)
    let (seed_bytes, cardano_src): (Vec<u8>, Option<(Vec<u8>, String)>) =
        if input.split_whitespace().count() > 1 {
            let passphrase = prompt("Optional BIP-39 passphrase (leave blank for none): ");
            let m = Mnemonic::parse(input).expect("Invalid mnemonic phrase");
            (m.to_seed(passphrase.as_str()).to_vec(), Some((m.to_entropy(), passphrase)))
        } else {
            (decode_hex(input).expect("Invalid hex seed string"), None)
        };

    // ---- Dust ----
    let dust_seed = derive_role_key(&seed_bytes, 2);
    let dust_pk = DustPublicKey::from(DustSecretKey::derive_secret_key(&dust_seed.into()));
    let mut dust_bytes = Vec::new();
    dust_pk.serialize(&mut dust_bytes).unwrap();

    // ---- Log Dust public key ----
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("\nDust public key:");
    println!("  serialized length: {} bytes", dust_bytes.len());
    println!("  hex (as serialized): {}", hex(&dust_bytes));

//    println!(
//        "  decimal (little-endian): {}",
//        num_bigint::BigUint::from_bytes_le(&dust_bytes)
//    );
//    println!(
//        "  decimal (big-endian):    {}",
//        num_bigint::BigUint::from_bytes_be(&dust_bytes)
//    );

    // ---- Shielded: coin public key (32) ++ encryption public key ----
    let zswap_seed = derive_role_key(&seed_bytes, 3);
    let keys = SecretKeys::from(Seed::from(zswap_seed));
    let mut shielded_bytes: Vec<u8> = keys.coin_public_key().0 .0.to_vec();
    keys.enc_public_key().serialize(&mut shielded_bytes).unwrap(); // VERIFY layout

    // ---- Unshielded: hash of the Schnorr verifying key ----
    let night_key = derive_role_key(&seed_bytes, 0);
    let sk = SigningKey::from_bytes(&night_key).expect("bad signing key");
    let unshielded_bytes: [u8; 32] = UserAddress::from(sk.verifying_key()).0 .0; // VERIFY

    for (net, cardano_id) in NETWORKS {
        println!("\n=== {net} ===");
        match &cardano_src {
            Some((entropy, pass)) => {
                let (base, reward) = cardano_addresses(entropy, pass, cardano_id);
                println!("Cardano base:   {base}");
                println!("Cardano reward: {reward}");
            }
            None => println!("Cardano:        (needs a mnemonic, not a hex seed)"),
        }
        println!("Unshielded:     {}", b32m(&hrp("mn_addr", net), &unshielded_bytes));
        println!("Shielded:       {}", b32m(&hrp("mn_shield-addr", net), &shielded_bytes));
        println!("Dust:           {}", b32m(&hrp("mn_dust", net), &dust_bytes));
    }
}
