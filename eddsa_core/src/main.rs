use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use rand::thread_rng;
use hex;
use std::env;
use std::process;
use std::time::Instant; // Добавлено для замера времени

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Использование:");
        eprintln!("  {} gen                     - generate keys (pub_hex, priv_hex)", args[0]);
        eprintln!("  {} sign <priv_hex> <msg_hex> - sign", args[0]);
        eprintln!("  {} verify <pub_hex> <msg_hex> <sig_hex> - verify", args[0]);
        eprintln!("  {} bench <iterations> <msg_hex> - benchmark core math", args[0]); // Добавлено
        process::exit(1);
    }

    match args[1].as_str() {
        "gen" => cmd_gen(),
        "sign" => {
            if args.len() < 4 {
                eprintln!("Ошибка: нужны priv_hex и msg_hex");
                process::exit(1);
            }
            cmd_sign(&args[2], &args[3]);
        }
        "verify" => {
            if args.len() < 5 {
                eprintln!("Ошибка: нужны pub_hex, msg_hex, sig_hex");
                process::exit(1);
            }
            cmd_verify(&args[2], &args[3], &args[4]);
        }
        "bench" => { // Новая команда
            if args.len() < 4 {
                eprintln!("Ошибка: нужны iterations и msg_hex");
                process::exit(1);
            }
            cmd_bench(&args[2], &args[3]);
        }
        _ => {
            eprintln!("Неизвестная команда: {}", args[1]);
            process::exit(1);
        }
    }
}

fn cmd_gen() {
    let mut csprng = thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    println!("{}", hex::encode(verifying_key.as_bytes()));
    println!("{}", hex::encode(signing_key.to_bytes()));
}

fn cmd_sign(priv_hex: &str, msg_hex: &str) {
    let priv_bytes = hex::decode(priv_hex).expect("Неверный hex приватного ключа");
    let priv_array: [u8; 32] = priv_bytes.try_into().expect("Приватный ключ должен быть 32 байта");
    let signing_key = SigningKey::from_bytes(&priv_array);
    let msg = hex::decode(msg_hex).expect("Неверный hex сообщения");
    let signature = signing_key.sign(&msg);
    println!("{}", hex::encode(signature.to_bytes()));
}

fn cmd_verify(pub_hex: &str, msg_hex: &str, sig_hex: &str) {
    let pub_bytes = hex::decode(pub_hex).expect("Неверный hex публичного ключа");
    let pub_array: [u8; 32] = pub_bytes.try_into().expect("Публичный ключ должен быть 32 байта");
    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .expect("Не удалось восстановить публичный ключ");
    let msg = hex::decode(msg_hex).expect("Неверный hex сообщения");
    let sig_bytes = hex::decode(sig_hex).expect("Неверный hex подписи");
    let sig_array: [u8; 64] = sig_bytes.try_into().expect("Подпись должна быть 64 байта");
    let signature = Signature::from_bytes(&sig_array);
    
    match verifying_key.verify_strict(&msg, &signature) {
        Ok(()) => println!("OK"),
        Err(_) => println!("FAIL"),
    }
}

// НОВАЯ ФУНКЦИЯ ДЛЯ ЧЕСТНОГО ТЕСТА СКОРОСТИ ED25519
fn cmd_bench(iterations_str: &str, msg_hex: &str) {
    let iterations: usize = iterations_str.parse().expect("Неверное число итераций");
    let msg = hex::decode(msg_hex).expect("Неверный hex сообщения");
    let mut csprng = thread_rng();

    // 1. Тест чистой генерации ключей
    let gen_start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(SigningKey::generate(&mut csprng));
    }
    let gen_total = gen_start.elapsed().as_secs_f64() * 1000.0;
    let gen_avg = gen_total / (iterations as f64);

    // Подготовка ключа для подписания
    let signing_key = SigningKey::generate(&mut csprng);

    // 2. Тест чистого подписания
    let sign_start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(signing_key.sign(&msg));
    }
    let sign_total = sign_start.elapsed().as_secs_f64() * 1000.0;
    let sign_avg = sign_total / (iterations as f64);

    println!("{:.6}", gen_avg);
    println!("{:.6}", sign_avg);
}
