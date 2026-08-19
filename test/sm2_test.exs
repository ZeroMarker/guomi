defmodule Guomi.SM2Test do
  use ExUnit.Case, async: true

  alias Guomi.SM2, as: SM2
  alias Guomi.SM2.Curve, as: Curve

  describe "supported?/0" do
    test "is always true for the pure Elixir implementation" do
      assert SM2.supported?()
    end
  end

  describe "generate_keypair/0" do
    test "generates valid keypair" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      assert byte_size(private_key) == 32
      assert byte_size(public_key) == 65
      assert :binary.first(public_key) == 0x04
    end

    test "generates different keypairs" do
      assert {:ok, priv1, pub1} = SM2.generate_keypair()
      assert {:ok, priv2, pub2} = SM2.generate_keypair()
      refute priv1 == priv2
      refute pub1 == pub2
    end

    test "generates private keys in the standard [1, n-2] range" do
      for _ <- 1..200 do
        assert {:ok, private_key, _public_key} = SM2.generate_keypair()
        priv = :binary.decode_unsigned(private_key, :big)
        assert priv > 0
        assert priv < Curve.n() - 1
      end
    end
  end

  describe "curve arithmetic" do
    test "computes modular inverse over the curve order" do
      order = Curve.n()
      inverse = Curve.mod_inv(2, order)

      assert inverse != 0
      assert rem(2 * inverse, order) == 1
    end

    test "scalar multiplication matches fixed SM2 curve vectors" do
      assert Curve.mul(Curve.generator(), 1) == Curve.generator()

      assert Curve.mul(Curve.generator(), 2) ==
               {0x56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52,
                0x31B7E7E6CC8189F668535CE0F8EAF1BD6DE84C182F6C8E716F780D3A970A23C3}

      assert Curve.mul(Curve.generator(), 3) ==
               {0xA97F7CD4B3C993B4BE2DAA8CDB41E24CA13F6BD945302244E26918F1D0509EBF,
                0x530B5DD88C688EF5CCC5CEC08A72150F7C400EE5CD045292AAACDD037458F6E6}
    end
  end

  describe "sign/2 and verify/3" do
    test "sign verify roundtrip" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      message = "guomi-sm2"

      assert {:ok, signature} = SM2.sign(message, private_key)
      assert {:ok, true} = SM2.verify(message, signature, public_key)
    end

    test "verify returns false for tampered message" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      {:ok, signature} = SM2.sign("original message", private_key)

      assert {:ok, false} = SM2.verify("tampered message", signature, public_key)
    end

    test "verify returns false for wrong public key" do
      assert {:ok, priv1, _pub1} = SM2.generate_keypair()
      assert {:ok, _priv2, pub2} = SM2.generate_keypair()
      {:ok, signature} = SM2.sign("test message", priv1)

      assert {:ok, false} = SM2.verify("test message", signature, pub2)
    end

    test "verify rejects malformed signature sizes" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()

      {:ok, <<r::binary-size(32), _s::binary-size(32)>> = signature} =
        SM2.sign("test", private_key)

      assert {:error, :invalid_signature} = SM2.verify("test", <<>>, public_key)
      assert {:error, :invalid_signature} = SM2.verify("test", r, public_key)

      assert {:error, :invalid_signature} = SM2.verify("test", signature <> signature, public_key)
    end

    test "verify returns false for in-range corrupted signature" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      {:ok, <<r::binary-size(32), _s::binary-size(32)>>} = SM2.sign("test", private_key)
      corrupted = r <> <<1::256-big>>

      assert {:ok, false} = SM2.verify("test", corrupted, public_key)
    end

    test "handles empty, binary, and iodata messages" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()

      for message <- ["", <<0, 1, 2, 3, 0, 255, 128>>, ["hello", " ", "world"]] do
        assert {:ok, signature} = SM2.sign(message, private_key)
        assert {:ok, true} = SM2.verify(message, signature, public_key)
      end
    end

    test "documents raw signature format" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()

      assert {:ok, <<r::binary-size(32), s::binary-size(32)>> = signature} =
               SM2.sign("format check", private_key)

      assert byte_size(r) == 32
      assert byte_size(s) == 32
      assert {:ok, true} = SM2.verify("format check", signature, public_key)
    end
  end

  describe "standard signatures" do
    test "matches the GB/T 32918.5 recommended-curve ZA and signature vector" do
      public_key =
        Base.decode16!(
          "04" <>
            "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020" <>
            "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
        )

      expected_za =
        Base.decode16!("B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3")

      signature =
        Base.decode16!(
          "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3" <>
            "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"
        )

      assert {:ok, ^expected_za} = SM2.user_identity_digest("1234567812345678", public_key)

      assert {:ok, true} =
               SM2.verify_standard(
                 "message digest",
                 signature,
                 public_key,
                 "1234567812345678"
               )
    end

    test "ZA is deterministic and binds the user ID and public key" do
      assert {:ok, _private_key, public_key} = SM2.generate_keypair()
      assert {:ok, _other_private_key, other_public_key} = SM2.generate_keypair()

      assert {:ok, za} = SM2.user_identity_digest("1234567812345678", public_key)
      assert byte_size(za) == 32
      assert {:ok, ^za} = SM2.user_identity_digest("1234567812345678", public_key)
      refute SM2.user_identity_digest("other", public_key) == {:ok, za}
      refute SM2.user_identity_digest("1234567812345678", other_public_key) == {:ok, za}
    end

    test "standard sign and verify require the same user ID" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      assert {:ok, signature} = SM2.sign_standard("message", private_key, "alice")
      assert {:ok, true} = SM2.verify_standard("message", signature, public_key, "alice")
      assert {:ok, false} = SM2.verify_standard("message", signature, public_key, "bob")
    end

    test "rejects user IDs whose bit length does not fit ENTLA" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      oversized = :binary.copy(<<0>>, 8192)

      assert {:error, :invalid_input} = SM2.user_identity_digest(oversized, public_key)
      assert {:error, :invalid_input} = SM2.sign_standard("message", private_key, oversized)
    end
  end

  describe "encrypt/2 and decrypt/2" do
    test "decrypt rejects ciphertext shorter than C1 plus C3" do
      assert {:error, :invalid_ciphertext} = SM2.decrypt(<<1, 2, 3>>, <<1::256-big>>)
    end

    test "encrypt/decrypt roundtrip for text, empty, binary, long, and iodata plaintexts" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()

      plaintexts = [
        "secret message",
        "",
        <<0, 1, 2, 3, 255, 128, 64>>,
        String.duplicate("abcdefghij", 100),
        ["hello", " ", "world"]
      ]

      for plaintext <- plaintexts do
        expected = IO.iodata_to_binary(plaintext)
        assert {:ok, ciphertext} = SM2.encrypt(plaintext, public_key)
        assert {:ok, ^expected} = SM2.decrypt(ciphertext, private_key)
      end
    end

    test "decrypt with wrong private key fails authentication" do
      assert {:ok, _priv1, pub1} = SM2.generate_keypair()
      assert {:ok, priv2, _pub2} = SM2.generate_keypair()
      {:ok, ciphertext} = SM2.encrypt("test", pub1)

      assert {:error, :decryption_failed} = SM2.decrypt(ciphertext, priv2)
    end

    test "decrypt with tampered ciphertext fails authentication" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      {:ok, ciphertext} = SM2.encrypt("test message", public_key)
      <<c1::binary-size(65), c2::binary-size(10), rest::binary>> = ciphertext
      tampered_c2 = :binary.copy(<<Bitwise.bxor(:binary.first(c2), 0xFF)>>, 10)

      assert {:error, :decryption_failed} = SM2.decrypt(c1 <> tampered_c2 <> rest, private_key)
    end

    test "ciphertext includes ephemeral public key and MAC overhead" do
      assert {:ok, _private_key, public_key} = SM2.generate_keypair()
      plaintext = "test"

      assert {:ok, ciphertext} = SM2.encrypt(plaintext, public_key)
      assert byte_size(ciphertext) > byte_size(plaintext)
      assert byte_size(ciphertext) >= 65 + 32
    end

    test "decrypt at exact 97-byte boundary" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()

      assert {:ok, ct} = SM2.encrypt("", public_key)
      assert byte_size(ct) == 97
      assert {:ok, ""} = SM2.decrypt(ct, private_key)
    end

    test "decrypt rejects 96-byte ciphertext" do
      assert {:ok, priv, _pub} = SM2.generate_keypair()

      assert {:error, :invalid_ciphertext} = SM2.decrypt(<<0::96*8>>, priv)
    end

    test "decrypt with an off-curve ephemeral point reports invalid ciphertext" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      {:ok, ciphertext} = SM2.encrypt("test", public_key)
      <<_c1::binary-size(65), rest::binary>> = ciphertext
      off_curve_c1 = <<0x04, 0::64*8>>

      assert {:error, :invalid_ciphertext} = SM2.decrypt(off_curve_c1 <> rest, private_key)
    end
  end

  describe "standard encryption" do
    test "decrypts the GB/T 32918.5 Annex C recommended-curve vector" do
      private_key =
        Base.decode16!("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8")

      ciphertext =
        Base.decode16!(
          "04" <>
            "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73" <>
            "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0" <>
            "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766" <>
            "21886CA989CA9C7D58087307CA93092D651EFA"
        )

      assert {:ok, "encryption standard"} = SM2.decrypt_standard(ciphertext, private_key)
    end

    test "roundtrips long messages with C1 || C3 || C2 framing" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      plaintext = :binary.copy("standard sm2 message ", 10)

      assert {:ok, ciphertext} = SM2.encrypt_standard(plaintext, public_key)
      assert byte_size(ciphertext) == 65 + 32 + byte_size(plaintext)
      assert {:ok, ^plaintext} = SM2.decrypt_standard(ciphertext, private_key)
    end

    test "decryption accepts n - 1, which is valid for encryption but not signing" do
      private_int = Curve.n() - 1
      private_key = <<private_int::256-big>>
      public_key = Curve.generator() |> Curve.mul(private_int) |> Curve.encode_public()

      assert {:ok, ciphertext} = SM2.encrypt_standard("encryption-only key", public_key)
      assert {:ok, "encryption-only key"} = SM2.decrypt_standard(ciphertext, private_key)
      assert {:error, :invalid_key} = SM2.sign_standard("message", private_key, "user")
    end

    test "standard KDF does not repeat a 32-byte mask block" do
      assert {:ok, _private_key, public_key} = SM2.generate_keypair()
      plaintext = :binary.copy(<<0>>, 64)

      assert {:ok, <<_c1::binary-size(65), _c3::binary-size(32), c2::binary>>} =
               SM2.encrypt_standard(plaintext, public_key)

      <<first::binary-size(32), second::binary-size(32)>> = c2
      refute first == second
    end

    test "rejects tampering, empty plaintext, and cross-format decryption" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      assert {:error, :invalid_input} = SM2.encrypt_standard("", public_key)
      assert {:ok, ciphertext} = SM2.encrypt_standard("message", public_key)
      last = byte_size(ciphertext) - 1
      <<prefix::binary-size(last), byte>> = ciphertext
      tampered = prefix <> <<Bitwise.bxor(byte, 1)>>

      assert {:error, :decryption_failed} = SM2.decrypt_standard(tampered, private_key)
      assert {:error, :invalid_ciphertext} = SM2.decrypt_standard(<<0>>, private_key)

      invalid_c1 = <<0x04, 0::64*8, 0::32*8, 1>>
      assert {:error, :decryption_failed} = SM2.decrypt_standard(invalid_c1, private_key)

      assert {:error, _reason} = SM2.decrypt(ciphertext, private_key)

      assert {:ok, legacy} = SM2.encrypt("message", public_key)
      assert {:error, _reason} = SM2.decrypt_standard(legacy, private_key)
    end
  end

  describe "invalid inputs" do
    test "invalid iodata is reported as invalid input" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      assert {:ok, signature} = SM2.sign("valid", private_key)

      assert {:error, :invalid_input} = SM2.sign(["valid", :not_iodata], private_key)
      assert {:error, :invalid_input} = SM2.verify([:not_iodata], signature, public_key)
      assert {:error, :invalid_input} = SM2.encrypt([:not_iodata], public_key)
    end

    test "sign with invalid private key size or range" do
      assert {:error, :invalid_key} = SM2.sign("test", <<0::31*8>>)
      assert {:error, :invalid_key} = SM2.sign("test", <<0::33*8>>)
      assert {:error, :invalid_key} = SM2.sign("test", <<0::256-big>>)

      order = Curve.n()
      assert {:error, :invalid_key} = SM2.sign("test", <<order::256-big>>)

      # n - 1 is outside the standard private key range [1, n - 2]. It must be
      # rejected deterministically instead of hanging in a sign retry loop
      # (regression: (1 + d) ≡ 0 (mod n) makes s always 0).
      assert {:error, :invalid_key} = SM2.sign("test", <<Curve.n() - 1::256-big>>)
    end

    test "verify with invalid public key" do
      assert {:ok, priv, _pub} = SM2.generate_keypair()
      {:ok, sig} = SM2.sign("test", priv)

      assert {:error, :invalid_key} = SM2.verify("test", sig, <<0::64*8>>)
      assert {:error, :invalid_key} = SM2.verify("test", sig, <<>>)
      assert {:error, :invalid_key} = SM2.verify("test", sig, <<0x05, 0::64*8>>)
    end

    test "encrypt with invalid public key is an invalid key, not decryption failure" do
      assert {:error, :invalid_key} = SM2.encrypt("test", <<0::64*8>>)
      assert {:error, :invalid_key} = SM2.encrypt("test", <<>>)
      assert {:error, :invalid_key} = SM2.encrypt("test", <<0x04, 0::64*8>>)
    end

    test "decrypt with invalid private key" do
      assert {:ok, private_key, public_key} = SM2.generate_keypair()
      {:ok, ct} = SM2.encrypt("test", public_key)

      assert {:error, :invalid_key} = SM2.decrypt(ct, <<0::31*8>>)
      assert {:error, :invalid_key} = SM2.decrypt(ct, <<0::33*8>>)
      assert {:error, :invalid_key} = SM2.decrypt(ct, <<0::256-big>>)
      assert {:ok, "test"} = SM2.decrypt(ct, private_key)
    end
  end
end
