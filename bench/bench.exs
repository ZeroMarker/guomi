# Guomi micro-benchmark.
#
# Usage:
#     mix run bench/bench.exs
#
# Reports wall-clock throughput for the pure-Elixir SM2/SM3/SM4 cores so
# performance regressions can be spotted during development.

defmodule Guomi.Bench do
  @moduledoc false

  @samples 5
  @warmups 1
  @sm2_iterations 20
  @large_size 1024 * 1024
  @small_size 1024

  defp sample(samples, iterations, fun) do
    for _ <- 1..samples do
      {us, _} = :timer.tc(fn -> Enum.each(1..iterations, fn _ -> fun.() end) end)
      us / iterations
    end
  end

  defp stats(values) do
    sorted = Enum.sort(values)
    {hd(sorted), Enum.at(sorted, div(length(sorted), 2)), List.last(sorted)}
  end

  defp time(label, iterations, fun) do
    Enum.each(1..@warmups, fn _ -> fun.() end)
    {minimum, median, maximum} = @samples |> sample(iterations, fun) |> stats()

    IO.puts(
      "#{String.pad_trailing(label, 30)} " <>
        "min/median/max #{format_duration(minimum)} / " <>
        "#{format_duration(median)} / #{format_duration(maximum)}"
    )
  end

  defp throughput(label, bytes, fun) do
    Enum.each(1..@warmups, fn _ -> fun.() end)
    rates = sample(@samples, 1, fun) |> Enum.map(&(bytes / &1))
    {minimum, median, maximum} = stats(rates)

    IO.puts(
      "#{String.pad_trailing(label, 30)} " <>
        "min/median/max #{format_rate(minimum)} / " <>
        "#{format_rate(median)} / #{format_rate(maximum)}"
    )
  end

  defp format_duration(us) when us >= 1000, do: "#{Float.round(us / 1000, 2)} ms/op"
  defp format_duration(us), do: "#{Float.round(us, 1)} us/op"
  defp format_rate(bytes_per_us), do: "#{Float.round(bytes_per_us, 1)} MB/s"

  defp print_environment do
    {os_family, os_name} = :os.type()

    IO.puts("Elixir:          #{System.version()}")
    IO.puts("OTP:             #{System.otp_release()}")
    IO.puts("ERTS:            #{:erlang.system_info(:version)}")
    IO.puts("OS:              #{os_family}/#{os_name}")
    IO.puts("Architecture:    #{:erlang.system_info(:system_architecture)}")
    IO.puts("Schedulers:      #{System.schedulers_online()}")
    IO.puts("Samples:         #{@samples}")
    IO.puts("Warmups:         #{@warmups}")
    IO.puts("Large message:   #{@large_size} bytes")
    IO.puts("Small message:   #{@small_size} bytes")
    IO.puts("SM2 iterations:  #{@sm2_iterations}\n")
  end

  def run do
    IO.puts("guomi #{Mix.Project.config()[:version]} benchmark\n")
    print_environment()

    # -- SM3 ------------------------------------------------------------------
    data_1m = :binary.copy("a", @large_size)
    data_1k = :binary.copy("a", @small_size)

    throughput("SM3 hash 1 MiB", @large_size, fn -> Guomi.SM3.hash(data_1m) end)
    throughput("SM3 hash 1 KiB", @small_size, fn -> Guomi.SM3.hash(data_1k) end)

    # -- SM4 ------------------------------------------------------------------
    key = :binary.copy(<<1, 2, 3, 4, 5, 6, 7, 8>>, 2)
    iv = :binary.copy(<<0>>, 16)

    throughput("SM4 ECB encrypt 1 MiB", @large_size, fn -> Guomi.SM4.encrypt(data_1m, key) end)

    throughput("SM4 CBC encrypt 1 MiB", @large_size, fn ->
      Guomi.SM4.encrypt_cbc(data_1m, key, iv)
    end)

    throughput("SM4 CTR encrypt 1 MiB", @large_size, fn ->
      Guomi.SM4.encrypt_ctr(data_1m, key, iv)
    end)

    # -- SM2 ------------------------------------------------------------------
    time("SM2 generate_keypair", @sm2_iterations, fn -> Guomi.SM2.generate_keypair() end)

    {:ok, priv, pub} = Guomi.SM2.generate_keypair()
    message = "guomi benchmark message"

    time("SM2 sign 32-byte message", @sm2_iterations, fn -> Guomi.SM2.sign(message, priv) end)

    {:ok, signature} = Guomi.SM2.sign(message, priv)

    time("SM2 verify signature", @sm2_iterations, fn ->
      Guomi.SM2.verify(message, signature, pub)
    end)

    time("SM2 encrypt 32-byte message", @sm2_iterations, fn ->
      Guomi.SM2.encrypt(message, pub)
    end)

    {:ok, ciphertext} = Guomi.SM2.encrypt(message, pub)

    time("SM2 decrypt 32-byte message", @sm2_iterations, fn ->
      Guomi.SM2.decrypt(ciphertext, priv)
    end)

    IO.puts("")
  end
end

Guomi.Bench.run()
