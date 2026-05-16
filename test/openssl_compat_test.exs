defmodule Guomi.OpenSSLCompatTest do
  use ExUnit.Case, async: true

  @key_hex "0123456789abcdef0123456789abcdef"
  @iv_hex "00112233445566778899aabbccddeeff"

  defp openssl do
    System.find_executable("openssl")
  end

  defp with_temp_file(contents, fun) do
    path = Path.join(System.tmp_dir!(), "guomi-openssl-#{System.unique_integer([:positive])}")
    File.write!(path, contents)

    try do
      fun.(path)
    after
      File.rm(path)
    end
  end

  defp with_temp_output(fun) do
    path = Path.join(System.tmp_dir!(), "guomi-openssl-out-#{System.unique_integer([:positive])}")

    try do
      fun.(path)
    after
      File.rm(path)
    end
  end

  defp run_openssl(args) do
    case openssl() do
      nil -> {:skip, :openssl_missing}
      bin -> System.cmd(bin, args, stderr_to_stdout: true)
    end
  end

  defp run_cli(args, input) do
    elixir = System.find_executable("elixir") || System.find_executable("elixir.bat")

    with_temp_file(input, fn input_path ->
      code = "Guomi.CLI.run(#{inspect(args ++ [input_path])})"

      System.cmd(elixir, ["-pa", Path.expand("_build/test/lib/guomi/ebin"), "-e", code],
        stderr_to_stdout: true
      )
    end)
  end

  defp openssl_sm3_hex(input) do
    with_temp_file(input, fn path ->
      case run_openssl(["sm3", "-hex", path]) do
        {:skip, _} = skip ->
          skip

        {output, 0} ->
          output
          |> String.trim()
          |> String.split()
          |> List.last()

        {_output, _status} ->
          {:skip, :sm3_missing}
      end
    end)
  end

  defp openssl_sm4(command, plaintext, args) do
    with_temp_file(plaintext, fn input_path ->
      with_temp_output(fn output_path ->
        case run_openssl(
               [command, "-K", @key_hex, "-in", input_path, "-out", output_path] ++ args
             ) do
          {:skip, _} = skip -> skip
          {_output, 0} -> File.read!(output_path)
          {_output, _status} -> {:skip, :sm4_missing}
        end
      end)
    end)
  end

  test "SM3 CLI output matches OpenSSL" do
    input = "The quick brown fox jumps over the lazy dog"

    case openssl_sm3_hex(input) do
      {:skip, _reason} ->
        :ok

      expected ->
        {actual, 0} = run_cli(["sm3", "--hex"], input)
        assert String.trim(actual) == expected
    end
  end

  test "SM4 ECB CLI encryption matches OpenSSL" do
    plaintext = "Hello, SM4!"

    case openssl_sm4("sm4-ecb", plaintext, []) do
      {:skip, _reason} ->
        :ok

      expected ->
        {actual, 0} = run_cli(["sm4", "--key", @key_hex, "--hex"], plaintext)
        assert Base.decode16!(String.trim(actual), case: :mixed) == expected
    end
  end

  test "SM4 CBC CLI encryption matches OpenSSL" do
    plaintext = "Test message for SM4 CBC mode verification"

    case openssl_sm4("sm4-cbc", plaintext, ["-iv", @iv_hex]) do
      {:skip, _reason} ->
        :ok

      expected ->
        {actual, 0} =
          run_cli(
            ["sm4", "--mode", "cbc", "--key", @key_hex, "--iv", @iv_hex, "--hex"],
            plaintext
          )

        assert Base.decode16!(String.trim(actual), case: :mixed) == expected
    end
  end
end
