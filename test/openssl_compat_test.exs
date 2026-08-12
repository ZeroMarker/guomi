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
      code = "Guomi.CLI.run(#{inspect(args ++ ["--file", input_path])})"

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
    with_temp_pair(plaintext, fn input_path, output_path ->
      command
      |> openssl_sm4_args(input_path, output_path, args)
      |> run_openssl()
      |> read_openssl_output(output_path, :sm4_missing)
    end)
  end

  defp with_temp_pair(input, fun) do
    with_temp_file(input, fn input_path ->
      with_temp_output(fn output_path -> fun.(input_path, output_path) end)
    end)
  end

  defp openssl_sm4_args(command, input_path, output_path, args) do
    [command, "-K", @key_hex, "-in", input_path, "-out", output_path] ++ args
  end

  defp read_openssl_output({:skip, _} = skip, _output_path, _missing_reason), do: skip

  defp read_openssl_output({_output, 0}, output_path, _missing_reason),
    do: File.read!(output_path)

  defp read_openssl_output({_output, _status}, _output_path, missing_reason),
    do: {:skip, missing_reason}

  defp sm2_private_pem(private_key, public_key) do
    oid_ec_public_key = <<0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01>>
    oid_sm2 = <<0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D>>

    ec_private_key =
      <<0x02, 0x01, 0x01, 0x04, 0x20>> <>
        private_key <>
        <<0xA1, 68, 0x03, 66, 0x00>> <>
        public_key

    algorithm = der_wrap(0x30, oid_ec_public_key <> oid_sm2)

    private_key_info =
      <<0x02, 0x01, 0x00>> <>
        algorithm <>
        der_wrap(0x04, der_wrap(0x30, ec_private_key))

    der = der_wrap(0x30, private_key_info)

    encoded =
      der
      |> Base.encode64()
      |> String.graphemes()
      |> Enum.chunk_every(64)
      |> Enum.map_join("\n", &Enum.join/1)

    "-----BEGIN PRIVATE KEY-----\n#{encoded}\n-----END PRIVATE KEY-----\n"
  end

  defp raw_signature_to_der(<<r::binary-size(32), s::binary-size(32)>>) do
    r = der_integer(r)
    s = der_integer(s)
    body = <<0x02, byte_size(r)>> <> r <> <<0x02, byte_size(s)>> <> s
    <<0x30, byte_size(body)>> <> body
  end

  defp der_signature_to_raw(
         <<0x30, _sequence_size, 0x02, r_size, r::binary-size(r_size), 0x02, s_size,
           s::binary-size(s_size)>>
       ) do
    pad_integer(r) <> pad_integer(s)
  end

  defp raw_ciphertext_to_der(
         <<0x04, x::binary-size(32), y::binary-size(32), c3::binary-size(32), c2::binary>>
       ) do
    body =
      der_wrap(0x02, der_integer(x)) <>
        der_wrap(0x02, der_integer(y)) <>
        der_wrap(0x04, c3) <>
        der_wrap(0x04, c2)

    der_wrap(0x30, body)
  end

  defp der_ciphertext_to_raw(der) do
    {0x30, body, <<>>} = take_der(der)
    {0x02, x, body} = take_der(body)
    {0x02, y, body} = take_der(body)
    {0x04, c3, body} = take_der(body)
    {0x04, c2, <<>>} = take_der(body)
    <<0x04>> <> pad_integer(x) <> pad_integer(y) <> c3 <> c2
  end

  defp der_wrap(tag, value) when byte_size(value) < 128,
    do: <<tag, byte_size(value)>> <> value

  defp der_wrap(tag, value) when byte_size(value) < 256,
    do: <<tag, 0x81, byte_size(value)>> <> value

  defp take_der(<<tag, length, rest::binary>>) when length < 128 do
    <<value::binary-size(length), tail::binary>> = rest
    {tag, value, tail}
  end

  defp take_der(<<tag, 0x81, length, rest::binary>>) do
    <<value::binary-size(length), tail::binary>> = rest
    {tag, value, tail}
  end

  defp der_integer(value) do
    value = trim_zeroes(value)
    if Bitwise.band(:binary.first(value), 0x80) == 0, do: value, else: <<0>> <> value
  end

  defp trim_zeroes(<<0, rest::binary>>) when byte_size(rest) > 0, do: trim_zeroes(rest)
  defp trim_zeroes(value), do: value

  defp pad_integer(<<0, rest::binary>>) when byte_size(rest) == 32, do: rest

  defp pad_integer(value) when byte_size(value) <= 32 do
    :binary.copy(<<0>>, 32 - byte_size(value)) <> value
  end

  defp with_sm2_files(message, private_key, public_key, fun) do
    with_temp_file(message, fn message_path ->
      with_sm2_key_file(message_path, private_key, public_key, fun)
    end)
  end

  defp with_sm2_key_file(message_path, private_key, public_key, fun) do
    with_temp_file(sm2_private_pem(private_key, public_key), fn key_path ->
      with_sm2_output_file(message_path, key_path, fun)
    end)
  end

  defp with_sm2_output_file(message_path, key_path, fun) do
    with_temp_output(fn output_path -> fun.(message_path, key_path, output_path) end)
  end

  test "SM3 CLI output matches OpenSSL" do
    input = "The quick brown fox jumps over the lazy dog"

    if Guomi.SM3.supported?() do
      case openssl_sm3_hex(input) do
        {:skip, _reason} ->
          :ok

        expected ->
          {actual, 0} = run_cli(["sm3", "--hex"], input)
          assert String.trim(actual) == expected
      end
    else
      assert true
    end
  end

  test "SM4 ECB CLI encryption matches OpenSSL" do
    plaintext = "Hello, SM4!"

    if Guomi.SM4.supported?() do
      case openssl_sm4("sm4-ecb", plaintext, []) do
        {:skip, _reason} ->
          :ok

        expected ->
          {actual, 0} = run_cli(["sm4", "--key", @key_hex, "--hex"], plaintext)
          assert Base.decode16!(String.trim(actual), case: :mixed) == expected
      end
    else
      assert true
    end
  end

  test "SM4 CBC CLI encryption matches OpenSSL" do
    plaintext = "Test message for SM4 CBC mode verification"

    if Guomi.SM4.supported?() do
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
    else
      assert true
    end
  end

  test "standard SM2 signatures interoperate with OpenSSL in both directions" do
    assert {:ok, private_key, public_key} = Guomi.SM2.generate_keypair()
    message = "Guomi and OpenSSL SM2 interoperability"
    user_id = "guomi-test-user"

    with_sm2_files(message, private_key, public_key, fn message_path, key_path, signature_path ->
      assert {:ok, raw_signature} =
               Guomi.SM2.sign_standard(message, private_key, user_id)

      File.write!(signature_path, raw_signature_to_der(raw_signature))

      verify_args = [
        "pkeyutl",
        "-verify",
        "-inkey",
        key_path,
        "-rawin",
        "-digest",
        "sm3",
        "-pkeyopt",
        "distid:#{user_id}",
        "-in",
        message_path,
        "-sigfile",
        signature_path
      ]

      case run_openssl(verify_args) do
        {:skip, reason} ->
          IO.puts("Skipping SM2 OpenSSL interoperability: #{reason}")

        {_output, 0} ->
          sign_args = [
            "pkeyutl",
            "-sign",
            "-inkey",
            key_path,
            "-rawin",
            "-digest",
            "sm3",
            "-pkeyopt",
            "distid:#{user_id}",
            "-in",
            message_path,
            "-out",
            signature_path
          ]

          assert {_output, 0} = run_openssl(sign_args)
          openssl_signature = signature_path |> File.read!() |> der_signature_to_raw()

          assert {:ok, true} =
                   Guomi.SM2.verify_standard(message, openssl_signature, public_key, user_id)

        {output, status} ->
          flunk("OpenSSL SM2 verification failed (#{status}): #{output}")
      end
    end)
  end

  test "standard SM2 encryption interoperates with OpenSSL in both directions" do
    assert {:ok, private_key, public_key} = Guomi.SM2.generate_keypair()
    message = "Guomi and OpenSSL SM2 encryption"

    with_sm2_files(message, private_key, public_key, fn message_path, key_path, ciphertext_path ->
      assert {:ok, raw_ciphertext} = Guomi.SM2.encrypt_standard(message, public_key)
      File.write!(ciphertext_path, raw_ciphertext_to_der(raw_ciphertext))

      with_temp_output(fn plaintext_path ->
        decrypt_args = [
          "pkeyutl",
          "-decrypt",
          "-inkey",
          key_path,
          "-in",
          ciphertext_path,
          "-out",
          plaintext_path
        ]

        case run_openssl(decrypt_args) do
          {:skip, reason} ->
            IO.puts("Skipping SM2 OpenSSL encryption interoperability: #{reason}")

          {_output, 0} ->
            assert File.read!(plaintext_path) == message

            encrypt_args = [
              "pkeyutl",
              "-encrypt",
              "-inkey",
              key_path,
              "-in",
              message_path,
              "-out",
              ciphertext_path
            ]

            assert {_output, 0} = run_openssl(encrypt_args)
            openssl_ciphertext = ciphertext_path |> File.read!() |> der_ciphertext_to_raw()

            assert {:ok, ^message} =
                     Guomi.SM2.decrypt_standard(openssl_ciphertext, private_key)

          {output, status} ->
            flunk("OpenSSL SM2 decryption failed (#{status}): #{output}")
        end
      end)
    end)
  end
end
