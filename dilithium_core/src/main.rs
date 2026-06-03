use pqc_dilithium::Keypair;
use pqc_dilithium::verify;
use hex;
use rand::thread_rng;
use rand::RngCore;
use std::env;
use std::process;
use std::time::Instant; // Добавили для замера времени

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Использование:");
        eprintln!("  {} gen                     - generate keys (pub_hex, seed_hex)", args[0]);
        eprintln!("  {} sign <seed_hex> <msg_hex> - sign", args[0]);
        eprintln!("  {} verify <pub_hex> <msg_hex> <sig_hex> - verify", args[0]);
        eprintln!("  {} bench <iterations> <msg_hex> - benchmark core math", args[0]); // Новая команда
        process::exit(1);
    }

    match args[1].as_str() {
        "gen" => cmd_gen(),
        "sign" => {
            if args.len() < 4 {
                eprintln!("Ошибка: нужны seed_hex и msg_hex");
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
        "bench" => {
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
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    let keys = Keypair::derive(&seed);
    let pk = keys.public;
    println!("{}", hex::encode(pk));
    println!("{}", hex::encode(seed));
}

fn cmd_sign(seed_hex: &str, msg_hex: &str) {
    let seed = hex::decode(seed_hex).expect("Неверный hex seed");
    let keys = Keypair::derive(&seed);
    let msg = hex::decode(msg_hex).expect("Неверный hex сообщения");
    let sig = keys.sign(&msg, false);  // false = детерминированная подпись
    println!("{}", hex::encode(sig));
}

fn cmd_verify(pub_hex: &str, msg_hex: &str, sig_hex: &str) {
    let pk = hex::decode(pub_hex).expect("Неверный hex публичного ключа");
    let msg = hex::decode(msg_hex).expect("Неверный hex сообщения");
    let sig = hex::decode(sig_hex).expect("Неверный hex подписи");
    match verify(&sig, &msg, &pk) {
        Ok(()) => println!("OK"),
        Err(_) => println!("FAIL"),
    }
}

// НОВАЯ ФУНКЦИЯ ДЛЯ ЧЕСТНОГО ТЕСТА СКОРОСТИ
fn cmd_bench(iterations_str: &str, msg_hex: &str) {
    let iterations: usize = iterations_str.parse().expect("Неверное число итераций");
    let msg = hex::decode(msg_hex).expect("Неверный hex сообщения");
    
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);

    // 1. Тестируем чистую генерацию ключей
    let gen_start = Instant::now();
    for _ in 0..iterations {
        // Мы используем std::hint::black_box, чтобы компилятор 
        // случайно не удалил "бесполезный" цикл при оптимизации --release
        std::hint::black_box(Keypair::derive(&seed));
    }
    let gen_total = gen_start.elapsed().as_secs_f64() * 1000.0; // в миллисекунды
    let gen_avg = gen_total / (iterations as f64);

    // Подготовка ключей для теста подписания
    let keys = Keypair::derive(&seed);

    // 2. Тестируем чистое подписание
    let sign_start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(keys.sign(&msg, false));
    }
    let sign_total = sign_start.elapsed().as_secs_f64() * 1000.0; // в миллисекунды
    let sign_avg = sign_total / (iterations as f64);

    // Выводим только чистые результаты (Python их распарсит)
    println!("{:.6}", gen_avg);
    println!("{:.6}", sign_avg);
}
