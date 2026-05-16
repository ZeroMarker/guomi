defmodule Guomi.CLITest do
  use ExUnit.Case, async: true

  @key "0123456789abcdef0123456789abcdef"

  defp run_cli(args, input \\ nil) do
    elixir = System.find_executable("elixir") || System.find_executable("elixir.bat")

    {args, input_path} =
      if is_binary(input) do
        input_path =
          Path.join(System.tmp_dir!(), "guomi-cli-#{System.unique_integer([:positive])}")

        File.write!(input_path, input)
        {args ++ [input_path], input_path}
      else
        {args, nil}
      end

    code = "Guomi.CLI.run(#{inspect(args)})"

    try do
      System.cmd(
        elixir,
        ["-pa", Path.expand("_build/test/lib/guomi/ebin"), "-e", code],
        stderr_to_stdout: true
      )
    after
      if input_path, do: File.rm(input_path)
    end
  end

  test "version prints package version" do
    {output, 0} = run_cli(["version"])
    assert output =~ "guomi v"
  end

  test "help prints command list" do
    {output, 0} = run_cli(["help"])
    assert output =~ "COMMANDS:"
    assert output =~ "sm3"
    assert output =~ "sm4"
    assert output =~ "sm2"
  end

  test "sm3 reads file input and prints hex output" do
    {output, 0} = run_cli(["sm3", "--hex"], "abc")

    assert String.trim(output) ==
             "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
  end

  test "sm4 reports missing key" do
    {output, status} = run_cli(["sm4"], "secret")
    assert status != 0
    assert output =~ "Missing required option --key"
  end

  test "sm4 reports invalid mode" do
    {output, status} = run_cli(["sm4", "--key", @key, "--mode", "ctr"], "secret")
    assert status != 0
    assert output =~ "Invalid mode: ctr"
  end

  test "sm4 reports invalid hex ciphertext" do
    {output, status} = run_cli(["sm4", "--decrypt", "--key", @key, "--hex"], "not-hex")
    assert status != 0
    assert output =~ "Invalid hex encoding for ciphertext"
  end

  test "sm2 decrypt reports missing ciphertext" do
    {output, status} = run_cli(["sm2", "--decrypt"])
    assert status != 0
    assert output =~ "Missing required option --ciphertext"
  end

  test "sm4 encrypts to hex and decrypts hex ciphertext" do
    if Guomi.SM4.supported?() do
      {ciphertext, 0} = run_cli(["sm4", "--key", @key, "--hex"], "secret")

      assert ciphertext =~ ~r/^[0-9a-f]+\r?\n$/

      {plaintext, 0} =
        run_cli(["sm4", "--decrypt", "--key", @key, "--hex"], String.trim(ciphertext))

      assert plaintext == "secret"
    end
  end

  test "sm4 supports explicit input and output hex flags" do
    if Guomi.SM4.supported?() do
      {ciphertext, 0} =
        run_cli(["sm4", "--key", @key, "--input-hex", "--output-hex"], "736563726574")

      assert ciphertext =~ ~r/^[0-9a-f]+\r?\n$/

      {plaintext_hex, 0} =
        run_cli(
          ["sm4", "--decrypt", "--key", @key, "--input-hex", "--output-hex"],
          String.trim(ciphertext)
        )

      assert String.trim(plaintext_hex) == "736563726574"
    end
  end
end
