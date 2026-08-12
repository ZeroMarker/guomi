# Guomi micro-benchmark.
#
# Usage:
#     mix run bench/bench.exs
#
# Reports wall-clock throughput for the pure-Elixir SM2/SM3/SM4 cores so
# performance regressions can be spotted during development.

defmodule Guomi.Bench do
  @moduledoc false

  def time(label, n, fun) do
    # warmup
    fun.()

    {us, _} = :timer.tc(fn -> Enum.each(1..n, fn _ -> fun.() end) end)

    per_op = us / n / 1000

    label = String.pad_trailing(label, 34)

    if per_op >= 1 do
      IO.puts("#{label} #{per_op |> Float.round(2)} ms/op")
    else
      IO.puts("#{label} #{us / n |> Float.round(1)} us/op")
    end
  end

  def run do
    IO.puts("guomi #{Mix.Project.config()[:version]} benchmark\n")

    # -- SM3 ------------------------------------------------------------------
    data_1m = :binary.copy("a", 1024 * 1024)
    data_1k = :binary.copy("a", 1024)

    {us, _} = :timer.tc(fn -> Guomi.SM3.hash(data_1m) end)
    IO.puts("SM3 hash 1 MiB                #{Float.round(1024 * 1024 / us, 1)} MB/s")

    {us, _} = :timer.tc(fn -> Enum.each(1..100, fn _ -> Guomi.SM3.hash(data_1k) end) end)
    IO.puts("SM3 hash 1 KiB x100           #{Float.round(100 * 1024 / us, 1)} MB/s")

    # -- SM4 ------------------------------------------------------------------
    key = :binary.copy(<<1, 2, 3, 4, 5, 6, 7, 8>>, 2)
    iv = :binary.copy(<<0>>, 16)

    {us, _} = :timer.tc(fn -> Guomi.SM4.encrypt(data_1m, key) end)
    IO.puts("SM4 ECB encrypt 1 MiB         #{Float.round(1024 * 1024 / us, 1)} MB/s")

    {us, _} = :timer.tc(fn -> Guomi.SM4.encrypt_cbc(data_1m, key, iv) end)
    IO.puts("SM4 CBC encrypt 1 MiB         #{Float.round(1024 * 1024 / us, 1)} MB/s")

    {us, _} = :timer.tc(fn -> Guomi.SM4.encrypt_ctr(data_1m, key, iv) end)
    IO.puts("SM4 CTR encrypt 1 MiB         #{Float.round(1024 * 1024 / us, 1)} MB/s")

    # -- SM2 ------------------------------------------------------------------
    time("SM2 generate_keypair", 20, fn -> Guomi.SM2.generate_keypair() end)

    {:ok, priv, pub} = Guomi.SM2.generate_keypair()
    message = "guomi benchmark message"

    time("SM2 sign 32-byte message", 20, fn -> Guomi.SM2.sign(message, priv) end)

    {:ok, signature} = Guomi.SM2.sign(message, priv)

    time("SM2 verify signature", 20, fn -> Guomi.SM2.verify(message, signature, pub) end)

    time("SM2 encrypt 32-byte message", 20, fn -> Guomi.SM2.encrypt(message, pub) end)

    {:ok, ciphertext} = Guomi.SM2.encrypt(message, pub)

    time("SM2 decrypt 32-byte message", 20, fn -> Guomi.SM2.decrypt(ciphertext, priv) end)

    IO.puts("")
  end
end

Guomi.Bench.run()
