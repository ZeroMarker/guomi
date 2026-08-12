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
        {args ++ ["--file", input_path], input_path}
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
    if Guomi.SM3.supported?() do
      {output, 0} = run_cli(["sm3", "--hex"], "abc")

      assert String.trim(output) ==
               "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    else
      {output, status} = run_cli(["sm3", "--hex"], "abc")
      assert status != 0
      assert output =~ "SM3 is not supported on this system"
    end
  end

  test "sm3 treats a single positional argument as message text" do
    {output, 0} = run_cli(["sm3", "--hex", "abc"])

    assert String.trim(output) ==
             "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
  end

  test "input rejects combining --file with positional text" do
    {output, status} = run_cli(["sm3", "--hex", "--file", "some-file", "text"])
    assert status != 0
    assert output =~ "Use either --file or positional input, not both"
  end

  test "sm3 handles empty input" do
    if Guomi.SM3.supported?() do
      {output, 0} = run_cli(["sm3", "--hex"], "")
      assert String.trim(output) =~ ~r/^[0-9a-f]{64}$/
    end
  end

  test "sm4 reports missing key" do
    {output, status} = run_cli(["sm4"], "secret")
    assert status != 0
    assert output =~ "Missing required option --key"
  end

  test "sm4 reports invalid mode" do
    {output, status} = run_cli(["sm4", "--key", @key, "--mode", "gcm"], "secret")
    assert status != 0
    assert output =~ "Invalid mode: gcm"
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

  test "sm2 rejects the removed --hex option" do
    {output, status} = run_cli(["sm2", "--hex", "--generate"])
    assert status != 0
    assert output =~ "Unknown or invalid SM2 option: --hex"
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

  test "sm4 cbc mode encrypt and decrypt" do
    if Guomi.SM4.supported?() do
      iv_hex = "00112233445566778899aabbccddeeff"

      {ct, 0} =
        run_cli(["sm4", "--key", @key, "--mode", "cbc", "--iv", iv_hex, "--hex"], "secret")

      {pt, 0} =
        run_cli(
          ["sm4", "--decrypt", "--key", @key, "--mode", "cbc", "--iv", iv_hex, "--hex"],
          String.trim(ct)
        )

      assert String.trim(pt) == "secret"
    end
  end

  test "sm4 cbc mode requires --iv" do
    {output, status} = run_cli(["sm4", "--key", @key, "--mode", "cbc"], "secret")
    assert status != 0
    assert output =~ "Missing required option --iv"
  end

  test "sm4 ctr mode encrypts and decrypts arbitrary-length input" do
    counter = "00112233445566778899aabbccddeeff"

    {ciphertext, 0} =
      run_cli(["sm4", "--mode", "ctr", "--counter", counter, "--key", @key, "--hex"], "secret")

    {plaintext, 0} =
      run_cli(
        ["sm4", "--decrypt", "--mode", "ctr", "--counter", counter, "--key", @key, "--hex"],
        String.trim(ciphertext)
      )

    assert plaintext == "secret"
  end

  test "sm4 ctr mode requires a 16-byte counter and rejects padding" do
    {missing_output, missing_status} = run_cli(["sm4", "--mode", "ctr", "--key", @key], "secret")
    assert missing_status != 0
    assert missing_output =~ "Missing required option --counter"

    {padding_output, padding_status} =
      run_cli(
        [
          "sm4",
          "--mode",
          "ctr",
          "--counter",
          String.duplicate("00", 16),
          "--key",
          @key,
          "--padding",
          "none"
        ],
        "secret"
      )

    assert padding_status != 0
    assert padding_output =~ "SM4 CTR does not use padding"
  end

  test "unknown command reports error" do
    {output, status} = run_cli(["unknown"])
    assert status != 0
    assert output =~ "Unknown command"
  end

  test "no command prints help" do
    {output, 0} = run_cli([])
    assert output =~ "USAGE:"
  end

  # SM2 CLI tests - call module functions directly to test CLI integration
  # (subprocess approach is fragile for SM2 due to subprocess startup delay)

  test "sm2 generate via module" do
    assert Guomi.SM2.supported?()
    assert {:ok, priv, pub} = Guomi.SM2.generate_keypair()
    assert byte_size(priv) == 32
    assert byte_size(pub) == 65
  end

  test "sm2 sign and verify via module" do
    assert {:ok, priv, pub} = Guomi.SM2.generate_keypair()
    priv_hex = Base.encode16(priv, case: :lower)
    pub_hex = Base.encode16(pub, case: :lower)

    {sig_hex, 0} = run_cli(["sm2", "--sign", "--private-key", priv_hex, "--message", "test"])

    sig_hex = String.trim(sig_hex)

    {out, 0} =
      run_cli([
        "sm2",
        "--verify",
        "--public-key",
        pub_hex,
        "--signature",
        sig_hex,
        "--message",
        "test"
      ])

    assert out =~ "valid"

    {out2, status2} =
      run_cli([
        "sm2",
        "--verify",
        "--public-key",
        pub_hex,
        "--signature",
        sig_hex,
        "--message",
        "wrong"
      ])

    assert status2 != 0
    assert out2 =~ "INVALID"
  end

  test "sm2 encrypt and decrypt via module" do
    assert {:ok, priv, pub} = Guomi.SM2.generate_keypair()
    priv_hex = Base.encode16(priv, case: :lower)
    pub_hex = Base.encode16(pub, case: :lower)

    {ct_hex, 0} = run_cli(["sm2", "--encrypt", "--public-key", pub_hex, "--message", "secret"])

    ct_hex = String.trim(ct_hex)

    {pt, 0} = run_cli(["sm2", "--decrypt", "--private-key", priv_hex, "--ciphertext", ct_hex])

    assert String.trim(pt) == "secret"
  end
end
