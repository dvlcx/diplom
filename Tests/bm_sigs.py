import hashlib
import os
import statistics
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from eddsa_core import EdDSACore
from ecdsa_core import ECDSACore
from dilithium_core import DilithiumCore


def benchmark_ed25519(iterations=1000):
    message = b"Test message"
    core = EdDSACore()  # используем бинарник с поддержкой команды "bench"

    # Вызываем тяжелый цикл внутри Rust всего один раз
    gen_avg, sign_avg = core.run_benchmark(iterations, message)

    return {
        "name": "Ed25519",
        "gen_avg": gen_avg,
        "sign_avg": sign_avg,
    }


def benchmark_eddsa(iterations=1000):
    gen_times, sign_times = [], []
    message = b"Test message"
    core = ECDSACore()  # работает в памяти Python через eth_keys, оставляем цикл тут

    for _ in range(iterations):
        start = time.perf_counter()
        public_key, private_key = core.generate()
        gen_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        signature = core.sign(private_key, message)
        sign_times.append(time.perf_counter() - start)

    return {
        "name": "ECDSA",
        "gen_avg": statistics.mean(gen_times) * 1000,
        "sign_avg": statistics.mean(sign_times) * 1000,
    }


def benchmark_mldsa65(iterations=1000):
    message = b"Test message"
    core = DilithiumCore()  # используем бинарник с поддержкой команды "bench"

    gen_avg, sign_avg = core.run_benchmark(iterations, message)

    return {
        "name": "ML-DSA",
        "gen_avg": gen_avg,
        "sign_avg": sign_avg,
    }


def print_results(results):
    for r in results:
        print(f"\n{r['name']}:")
        print(f"  Генерация ключей: {r['gen_avg']:.3f} с")
        print(f"  Подпись:          {r['sign_avg']:.3f} с")
    print("=" * 80)


if __name__ == "__main__":
    iterations = 1000
    results = []
    results.append(benchmark_ed25519(iterations))
    results.append(benchmark_eddsa(iterations))
    results.append(benchmark_mldsa65(iterations))
    print_results(results)
