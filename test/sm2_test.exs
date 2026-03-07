defmodule Guomi.SM2Test do
  use ExUnit.Case, async: true

  describe "supported?/0" do
    test "returns boolean" do
      assert is_boolean(Guomi.SM2.supported?())
    end
  end

  describe "generate_keypair/0" do
    test "generates valid keypair when supported" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, public_key} ->
          assert byte_size(private_key) == 32
          assert byte_size(public_key) == 65
          assert :binary.first(public_key) == 0x04

        {:error, :unsupported} ->
          assert true
      end
    end

    test "generates different keypairs" do
      case Guomi.SM2.generate_keypair() do
        {:ok, priv1, pub1} ->
          {:ok, priv2, pub2} = Guomi.SM2.generate_keypair()
          refute priv1 == priv2
          refute pub1 == pub2

        {:error, :unsupported} ->
          assert true
      end
    end
  end

  describe "sign/2 and verify/3" do
    test "sign verify roundtrip when supported" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, public_key} ->
          message = "guomi-sm2"
          assert {:ok, signature} = Guomi.SM2.sign(message, private_key)
          assert {:ok, true} = Guomi.SM2.verify(message, signature, public_key)

        {:error, :unsupported} ->
          assert true
      end
    end

    test "verify returns false for tampered message" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, public_key} ->
          message = "original message"
          {:ok, signature} = Guomi.SM2.sign(message, private_key)
          tampered = "tampered message"
          assert {:ok, false} = Guomi.SM2.verify(tampered, signature, public_key)

        {:error, :unsupported} ->
          assert true
      end
    end

    test "verify returns false for wrong public key" do
      case Guomi.SM2.generate_keypair() do
        {:ok, _private_key, _public_key} ->
          {:ok, _priv2, pub2} = Guomi.SM2.generate_keypair()
          {:ok, priv1, _pub1} = Guomi.SM2.generate_keypair()
          message = "test message"
          {:ok, signature} = Guomi.SM2.sign(message, priv1)
          assert {:ok, false} = Guomi.SM2.verify(message, signature, pub2)

        {:error, :unsupported} ->
          assert true
      end
    end

    test "verify returns false for corrupted signature" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, public_key} ->
          message = "test"
          {:ok, signature} = Guomi.SM2.sign(message, private_key)
          <<head::binary-size(60), _rest::binary>> = signature
          corrupted = head <> <<0xFF, 0xFF>>
          assert {:ok, false} = Guomi.SM2.verify(message, corrupted, public_key)

        {:error, :unsupported} ->
          assert true
      end
    end

    test "handles empty message" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, public_key} ->
          message = ""
          assert {:ok, signature} = Guomi.SM2.sign(message, private_key)
          assert {:ok, true} = Guomi.SM2.verify(message, signature, public_key)

        {:error, :unsupported} ->
          assert true
      end
    end

    test "handles binary message with null bytes" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, public_key} ->
          message = <<0, 1, 2, 3, 0, 255, 128>>
          assert {:ok, signature} = Guomi.SM2.sign(message, private_key)
          assert {:ok, true} = Guomi.SM2.verify(message, signature, public_key)

        {:error, :unsupported} ->
          assert true
      end
    end

    test "signature has expected size" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, _public_key} ->
          {:ok, signature} = Guomi.SM2.sign("test", private_key)
          assert byte_size(signature) == 64

        {:error, :unsupported} ->
          assert true
      end
    end

    test "handles iodata message" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, public_key} ->
          message = ["hello", " ", "world"]
          assert {:ok, signature} = Guomi.SM2.sign(message, private_key)
          assert {:ok, true} = Guomi.SM2.verify(message, signature, public_key)

        {:error, :unsupported} ->
          assert true
      end
    end
  end

  describe "encrypt/2" do
    test "returns unsupported for current implementation" do
      case Guomi.SM2.generate_keypair() do
        {:ok, _private_key, public_key} ->
          assert {:error, :unsupported} = Guomi.SM2.encrypt("test", public_key)

        {:error, :unsupported} ->
          assert true
      end
    end
  end

  describe "decrypt/2" do
    test "returns unsupported for current implementation" do
      case Guomi.SM2.generate_keypair() do
        {:ok, private_key, _public_key} ->
          assert {:error, :unsupported} = Guomi.SM2.decrypt(<<1, 2, 3>>, private_key)

        {:error, :unsupported} ->
          assert true
      end
    end
  end
end
