# Benchmark Recording

Run benchmarks from a clean checkout with no other CPU-intensive workload:

```bash
mix run bench/bench.exs | tee bench/results/guomi-<version>-<date>-<host>.txt
```

The script records Elixir, OTP, ERTS, operating system, architecture, scheduler count, message sizes, warmups, samples and SM2 iteration count. Results report min/median/max; use the median for routine comparison and retain the range as noise context.

## Comparison rules

- Compare results only when architecture, scheduler count, runtime versions and message sizes match.
- Run both the baseline commit and candidate commit on the same host and power profile.
- Keep raw output under `bench/results/` in release or performance PR artifacts; do not commit machine-specific results by default.
- Treat a repeatable median regression above 10% as investigation-worthy, not automatically as a release failure.
- Re-run at least twice before drawing a conclusion. Single wall-clock samples are not performance evidence.
- Record the compared Git commits and any VM/container/CPU-frequency constraints beside the raw output.

`bench/results/` is a result exchange convention, not a CI gate. A future gate should use dedicated, stable hardware and a statistically justified threshold.
