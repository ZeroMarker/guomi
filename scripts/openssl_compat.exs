#!/usr/bin/env elixir

defmodule Guomi.OpenSSLCompatibilityScript do
  @key_hex "0123456789abcdef0123456789abcdef"
  @iv_hex "00112233445566778899aabbccddeeff"

  def run! do
    File.cd!(Path.expand("..", __DIR__))
    openssl_version = command!("openssl", ["version"], "OpenSSL") |> String.trim()
    tmp_dir = make_tmp_dir()

    try do
      IO.puts("OpenSSL compatibility check")
      IO.puts("  #{openssl_version}")
      ensure_algorithms!()
      run_sm4_matrix!(tmp_dir)
      run_exunit_compatibility_tests!()
      IO.puts("OpenSSL compatibility check passed")
    after
      File.rm_rf!(tmp_dir)
    end
  end

  defp ensure_algorithms! do
    digest_algorithms =
      command!("openssl", ["list", "-digest-algorithms"], "OpenSSL digest algorithms")

    cipher_algorithms =
      command!("openssl", ["list", "-cipher-algorithms"], "OpenSSL cipher algorithms")

    public_key_algorithms =
      command!("openssl", ["list", "-public-key-algorithms"], "OpenSSL public-key algorithms")

    ensure_contains!(digest_algorithms, "sm3", "SM3")
    ensure_contains!(cipher_algorithms, "sm4-ecb", "SM4-ECB")
    ensure_contains!(cipher_algorithms, "sm4-cbc", "SM4-CBC")
    ensure_contains!(cipher_algorithms, "sm4-ctr", "SM4-CTR")
    ensure_contains!(public_key_algorithms, "sm2", "SM2")
  end

  defp run_sm4_matrix!(tmp_dir) do
    key = Base.decode16!(@key_hex, case: :mixed)
    iv = Base.decode16!(@iv_hex, case: :mixed)
    message = "Guomi/OpenSSL cross implementation verification message"

    cases = [
      {"sm4-ecb", [], fn data -> Guomi.SM4.encrypt(data, key) end,
       fn data -> Guomi.SM4.decrypt(data, key) end},
      {"sm4-cbc", ["-iv", @iv_hex], fn data -> Guomi.SM4.encrypt_cbc(data, key, iv) end,
       fn data -> Guomi.SM4.decrypt_cbc(data, key, iv) end},
      {"sm4-ctr", ["-iv", @iv_hex], fn data -> Guomi.SM4.encrypt_ctr(data, key, iv) end,
       fn data -> Guomi.SM4.decrypt_ctr(data, key, iv) end}
    ]

    Enum.each(cases, fn {cipher, openssl_args, encrypt, decrypt} ->
      openssl_ciphertext = openssl_crypt!(tmp_dir, cipher, message, openssl_args)
      {:ok, from_openssl} = decrypt.(openssl_ciphertext)
      {:ok, guomi_ciphertext} = encrypt.(message)
      from_guomi = openssl_crypt!(tmp_dir, cipher, guomi_ciphertext, ["-d" | openssl_args])

      ensure_equal!(guomi_ciphertext, openssl_ciphertext, "#{cipher} ciphertext")
      ensure_equal!(from_openssl, message, "#{cipher} OpenSSL -> Guomi plaintext")
      ensure_equal!(from_guomi, message, "#{cipher} Guomi -> OpenSSL plaintext")

      IO.puts("  #{cipher}: exact ciphertext and bidirectional decryption passed")
    end)
  end

  defp run_exunit_compatibility_tests! do
    {output, status} =
      System.cmd("mix", ["test", "test/openssl_compat_test.exs", "--trace"],
        env: [{"GUOMI_REQUIRE_OPENSSL", "1"}],
        stderr_to_stdout: true
      )

    if status != 0 do
      IO.write(output)
      raise "OpenSSL ExUnit compatibility tests failed with status #{status}"
    end

    IO.write(output)
  end

  defp openssl_crypt!(tmp_dir, cipher, input, args) do
    input_path = Path.join(tmp_dir, "input-#{System.unique_integer([:positive])}")
    output_path = Path.join(tmp_dir, "output-#{System.unique_integer([:positive])}")
    File.write!(input_path, input)

    try do
      output =
        command!(
          "openssl",
          [cipher, "-K", @key_hex, "-in", input_path, "-out", output_path] ++ args,
          cipher
        )

      _ = output
      File.read!(output_path)
    after
      File.rm(input_path)
      File.rm(output_path)
    end
  end

  defp command!(command, args, description) do
    case System.cmd(command, args, stderr_to_stdout: true) do
      {output, 0} ->
        output

      {output, status} ->
        raise "#{description} failed with status #{status}: #{String.trim(output)}"
    end
  end

  defp ensure_contains!(value, expected, label) do
    if String.contains?(String.downcase(value), String.downcase(expected)) do
      :ok
    else
      raise "#{label} is unavailable in OpenSSL output"
    end
  end

  defp ensure_equal!(actual, expected, label) do
    if actual != expected do
      raise "#{label} mismatch"
    end
  end

  defp make_tmp_dir do
    path =
      Path.join(System.tmp_dir!(), "guomi-openssl-script-#{System.unique_integer([:positive])}")

    File.mkdir_p!(path)
    path
  end
end

Guomi.OpenSSLCompatibilityScript.run!()
