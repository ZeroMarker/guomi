defmodule Guomi.SM3Test do
  use ExUnit.Case, async: true

  describe "hash/1" do
    test "hash_hex for abc matches official vector" do
      assert Guomi.SM3.hash_hex("abc") ==
               "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    end

    test "binary hash is 32 bytes" do
      assert byte_size(Guomi.SM3.hash("hello")) == 32
    end

    test "empty string hash" do
      result = Guomi.SM3.hash_hex("")
      assert byte_size(result) == 64
    end

    test "same input produces same output" do
      assert Guomi.SM3.hash_hex("test") == Guomi.SM3.hash_hex("test")
    end

    test "different inputs produce different outputs" do
      assert Guomi.SM3.hash_hex("test1") != Guomi.SM3.hash_hex("test2")
    end

    test "handles binary input with null bytes" do
      data = <<0, 1, 2, 3, 255, 128>>
      assert byte_size(Guomi.SM3.hash(data)) == 32
    end

    test "handles chinese characters" do
      result = Guomi.SM3.hash_hex("国密算法SM3")
      assert byte_size(result) == 64
    end

    test "handles long input" do
      data = String.duplicate("a", 10_000)
      assert byte_size(Guomi.SM3.hash(data)) == 32
    end
  end

  describe "hash_hex/1" do
    test "returns lowercase hex string" do
      result = Guomi.SM3.hash_hex("ABC")
      assert result == String.downcase(result)
    end

    test "hex string length is 64 for any input" do
      assert byte_size(Guomi.SM3.hash_hex("")) == 64
      assert byte_size(Guomi.SM3.hash_hex("a")) == 64
      assert byte_size(Guomi.SM3.hash_hex("hello world")) == 64
    end
  end

  describe "supported?/0" do
    test "returns boolean" do
      assert is_boolean(Guomi.SM3.supported?())
    end
  end
end
