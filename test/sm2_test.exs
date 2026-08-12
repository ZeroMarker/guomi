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

      assert {:error, :invalid_signature} =
               SM2.verify("test", signature <> signature, public_key)
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

      assert {:error, :decryption_failed} =
               SM2.decrypt(c1 <> tampered_c2 <> rest, private_key)
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
  end

  describe "invalid inputs" do
    test "sign with invalid private key size or range" do
      assert {:error, :invalid_key} = SM2.sign("test", <<0::31*8>>)
      assert {:error, :invalid_key} = SM2.sign("test", <<0::33*8>>)
      assert {:error, :invalid_key} = SM2.sign("test", <<0::256-big>>)

      order = Curve.n()
      assert {:error, :invalid_key} = SM2.sign("test", <<order::256-big>>)
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
