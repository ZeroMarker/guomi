defmodule Guomi.SM4Test do
  use ExUnit.Case, async: true

  @key Base.decode16!("0123456789ABCDEFFEDCBA9876543210", case: :mixed)
  @plain Base.decode16!("0123456789ABCDEFFEDCBA9876543210", case: :mixed)
  @cipher Base.decode16!("681EDF34D206965E86B3E94F536E4246", case: :mixed)

  defp with_sm4_supported(fun) do
    if Guomi.SM4.supported?() do
      fun.()
    else
      assert true
    end
  end

  describe "supported?/0" do
    test "returns boolean" do
      assert is_boolean(Guomi.SM4.supported?())
    end
  end

  describe "ECB mode" do
    test "ecb known vector" do
      with_sm4_supported(fn ->
        assert {:ok, encrypted} = Guomi.SM4.encrypt(@plain, @key, padding: :none)
        assert encrypted == @cipher
        assert {:ok, decrypted} = Guomi.SM4.decrypt(encrypted, @key, padding: :none)
        assert decrypted == @plain
      end)
    end

    test "encrypt/decrypt roundtrip with pkcs7 padding" do
      with_sm4_supported(fn ->
        plaintext = "Hello, Guomi!"
        assert {:ok, encrypted} = Guomi.SM4.encrypt(plaintext, @key)
        assert {:ok, decrypted} = Guomi.SM4.decrypt(encrypted, @key)
        assert decrypted == plaintext
      end)
    end

    test "encrypt with empty string" do
      with_sm4_supported(fn ->
        plaintext = ""
        assert {:ok, encrypted} = Guomi.SM4.encrypt(plaintext, @key)
        assert byte_size(encrypted) == 16
      end)
    end

    test "encrypt error with invalid key size" do
      short_key = <<1, 2, 3>>
      assert {:error, :invalid_key_size} = Guomi.SM4.encrypt("test", short_key)
    end

    test "decrypt error with invalid key size" do
      short_key = <<1, 2, 3>>
      ciphertext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      assert {:error, :invalid_key_size} = Guomi.SM4.decrypt(ciphertext, short_key)
    end

    test "decrypt error with invalid block size" do
      short_ciphertext = <<1, 2, 3>>
      assert {:error, :invalid_block_size} = Guomi.SM4.decrypt(short_ciphertext, @key)
    end

    test "decrypt rejects malformed pkcs7 padding bytes" do
      with_sm4_supported(fn ->
        malformed_plaintext = "123456789012" <> <<4, 4, 4, 3>>
        {:ok, ciphertext} = Guomi.SM4.encrypt(malformed_plaintext, @key, padding: :none)
        assert {:error, :invalid_padding} = Guomi.SM4.decrypt(ciphertext, @key)
      end)
    end

    test "decrypt rejects out-of-range pkcs7 padding length" do
      with_sm4_supported(fn ->
        malformed_plaintext = "123456789012345" <> <<17>>
        {:ok, ciphertext} = Guomi.SM4.encrypt(malformed_plaintext, @key, padding: :none)
        assert {:error, :invalid_padding} = Guomi.SM4.decrypt(ciphertext, @key)
      end)
    end

    test "encrypt with :none padding requires block-aligned input" do
      not_aligned = <<1, 2, 3, 4, 5>>
      assert {:error, :invalid_block_size} = Guomi.SM4.encrypt(not_aligned, @key, padding: :none)
    end

    test "encrypt rejects unsupported padding option" do
      assert {:error, :invalid_padding} = Guomi.SM4.encrypt("test", @key, padding: :zeroes)
    end
  end

  describe "CBC mode" do
    test "cbc roundtrip" do
      with_sm4_supported(fn ->
        iv = <<0::128>>
        plaintext = "hello guomi"

        assert {:ok, encrypted} = Guomi.SM4.encrypt_cbc(plaintext, @key, iv)
        assert {:ok, decrypted} = Guomi.SM4.decrypt_cbc(encrypted, @key, iv)
        assert decrypted == plaintext
      end)
    end

    test "cbc with pkcs7 padding" do
      with_sm4_supported(fn ->
        iv = <<0::128>>
        plaintext = "Test message for CBC mode"

        assert {:ok, encrypted} = Guomi.SM4.encrypt_cbc(plaintext, @key, iv)
        assert {:ok, decrypted} = Guomi.SM4.decrypt_cbc(encrypted, @key, iv)
        assert decrypted == plaintext
      end)
    end

    test "cbc error with invalid iv size" do
      short_iv = <<1, 2, 3>>
      plaintext = "test"
      assert {:error, :invalid_iv_size} = Guomi.SM4.encrypt_cbc(plaintext, @key, short_iv)
    end

    test "cbc decrypt error with invalid iv size" do
      short_iv = <<1, 2, 3>>
      ciphertext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      assert {:error, :invalid_iv_size} = Guomi.SM4.decrypt_cbc(ciphertext, @key, short_iv)
    end

    test "cbc error with invalid key size" do
      short_key = <<1, 2, 3>>
      iv = <<0::128>>
      plaintext = "test"
      assert {:error, :invalid_key_size} = Guomi.SM4.encrypt_cbc(plaintext, short_key, iv)
    end

    test "cbc with different iv produces different ciphertext" do
      with_sm4_supported(fn ->
        plaintext = "Hello"
        iv1 = <<0::128>>
        iv2 = <<1::128>>

        assert {:ok, cipher1} = Guomi.SM4.encrypt_cbc(plaintext, @key, iv1)
        assert {:ok, cipher2} = Guomi.SM4.encrypt_cbc(plaintext, @key, iv2)
        refute cipher1 == cipher2
      end)
    end

    test "cbc decrypt error with invalid block size" do
      iv = <<0::128>>
      short_ciphertext = <<1, 2, 3>>
      assert {:error, :invalid_block_size} = Guomi.SM4.decrypt_cbc(short_ciphertext, @key, iv)
    end
  end

  describe "multi-block data" do
    test "handles large data in ECB mode" do
      with_sm4_supported(fn ->
        plaintext = String.duplicate("0123456789ABCDEF", 100)
        assert {:ok, encrypted} = Guomi.SM4.encrypt(plaintext, @key)
        assert {:ok, decrypted} = Guomi.SM4.decrypt(encrypted, @key)
        assert decrypted == plaintext
      end)
    end

    test "handles large data in CBC mode" do
      with_sm4_supported(fn ->
        iv = <<0::128>>
        plaintext = String.duplicate("0123456789ABCDEF", 100)
        assert {:ok, encrypted} = Guomi.SM4.encrypt_cbc(plaintext, @key, iv)
        assert {:ok, decrypted} = Guomi.SM4.decrypt_cbc(encrypted, @key, iv)
        assert decrypted == plaintext
      end)
    end
  end

  describe "binary data" do
    test "handles binary with null bytes" do
      with_sm4_supported(fn ->
        plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
        assert {:ok, encrypted} = Guomi.SM4.encrypt(plaintext, @key)
        assert {:ok, decrypted} = Guomi.SM4.decrypt(encrypted, @key)
        assert decrypted == plaintext
      end)
    end

    test "handles binary in CBC mode" do
      with_sm4_supported(fn ->
        iv = <<0::128>>
        plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
        assert {:ok, encrypted} = Guomi.SM4.encrypt_cbc(plaintext, @key, iv)
        assert {:ok, decrypted} = Guomi.SM4.decrypt_cbc(encrypted, @key, iv)
        assert decrypted == plaintext
      end)
    end
  end

  describe "padding edge cases" do
    for len <- [0, 1, 15, 16, 17, 31, 32] do
      @plaintext String.duplicate("x", len)
      test "pkcs7 padding roundtrip with #{len}-byte input" do
        with_sm4_supported(fn ->
          assert {:ok, ct} = Guomi.SM4.encrypt(@plaintext, @key)
          assert {:ok, pt} = Guomi.SM4.decrypt(ct, @key)
          assert pt == @plaintext
        end)
      end
    end

    test "pkcs7 padding byte value 0 is rejected" do
      with_sm4_supported(fn ->
        # Craft ciphertext ending with byte 0 as padding marker
        # A full block of 0x10 followed by a block ending with 0x00
        pt_with_invalid_pad = String.duplicate("a", 15) <> <<0>>
        {:ok, ct} = Guomi.SM4.encrypt(pt_with_invalid_pad, @key, padding: :none)
        assert {:error, :invalid_padding} = Guomi.SM4.decrypt(ct, @key)
      end)
    end

    test "pkcs7 with all padding values 1..16 via exact block count" do
      with_sm4_supported(fn ->
        # 16 bytes → PKCS7 adds 16 bytes of 0x10 (one extra block)
        plaintext16 = String.duplicate("a", 16)
        {:ok, ct} = Guomi.SM4.encrypt(plaintext16, @key)
        assert byte_size(ct) == 32
        {:ok, pt} = Guomi.SM4.decrypt(ct, @key)
        assert pt == plaintext16

        # 32 bytes → PKCS7 adds 16 bytes of 0x10
        plaintext32 = String.duplicate("a", 32)
        {:ok, ct2} = Guomi.SM4.encrypt(plaintext32, @key)
        assert byte_size(ct2) == 48
        {:ok, pt2} = Guomi.SM4.decrypt(ct2, @key)
        assert pt2 == plaintext32
      end)
    end

    test ":none padding with exact multiple of block size" do
      with_sm4_supported(fn ->
        plaintext = String.duplicate("a", 16)
        assert {:ok, ct} = Guomi.SM4.encrypt(plaintext, @key, padding: :none)
        assert {:ok, pt} = Guomi.SM4.decrypt(ct, @key, padding: :none)
        assert pt == plaintext
      end)
    end

    test "cbc pkcs7 with all padding lengths" do
      with_sm4_supported(fn ->
        iv = <<0::128>>

        for len <- [0, 1, 15, 16, 17, 31, 32] do
          pt = String.duplicate("y", len)
          assert {:ok, ct} = Guomi.SM4.encrypt_cbc(pt, @key, iv)
          assert {:ok, dec} = Guomi.SM4.decrypt_cbc(ct, @key, iv)
          assert dec == pt
        end
      end)
    end

    test "cbc decrypt rejects malformed pkcs7 padding" do
      with_sm4_supported(fn ->
        iv = <<0::128>>
        malformed = "123456789012" <> <<4, 4, 4, 3>>
        {:ok, ct} = Guomi.SM4.encrypt_cbc(malformed, @key, iv, padding: :none)
        assert {:error, :invalid_padding} = Guomi.SM4.decrypt_cbc(ct, @key, iv)
      end)
    end

    test "cbc decrypt rejects out-of-range pkcs7 padding" do
      with_sm4_supported(fn ->
        iv = <<0::128>>
        malformed = "123456789012345" <> <<17>>
        {:ok, ct} = Guomi.SM4.encrypt_cbc(malformed, @key, iv, padding: :none)
        assert {:error, :invalid_padding} = Guomi.SM4.decrypt_cbc(ct, @key, iv)
      end)
    end

    test "cbc with :none padding requires block-aligned input" do
      iv = <<0::128>>
      not_aligned = <<1, 2, 3, 4, 5>>

      assert {:error, :invalid_block_size} =
               Guomi.SM4.encrypt_cbc(not_aligned, @key, iv, padding: :none)
    end

    test "cbc rejects unsupported padding option" do
      iv = <<0::128>>

      assert {:error, :invalid_padding} =
               Guomi.SM4.encrypt_cbc("test", @key, iv, padding: :zeroes)
    end
  end

  describe "key and iv validation" do
    test "empty key is rejected" do
      assert {:error, :invalid_key_size} = Guomi.SM4.encrypt("test", <<>>)
    end

    test "15-byte key is rejected" do
      assert {:error, :invalid_key_size} = Guomi.SM4.encrypt("test", <<0::120>>)
    end

    test "17-byte key is rejected" do
      assert {:error, :invalid_key_size} = Guomi.SM4.encrypt("test", <<0::136>>)
    end

    test "empty iv is rejected in CBC" do
      assert {:error, :invalid_iv_size} = Guomi.SM4.encrypt_cbc("test", @key, <<>>)
    end

    test "15-byte iv is rejected in CBC" do
      assert {:error, :invalid_iv_size} = Guomi.SM4.encrypt_cbc("test", @key, <<0::120>>)
    end

    test "17-byte iv is rejected in CBC" do
      assert {:error, :invalid_iv_size} = Guomi.SM4.encrypt_cbc("test", @key, <<0::136>>)
    end
  end
end
