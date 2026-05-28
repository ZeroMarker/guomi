defmodule Guomi.SM3Test do
  use ExUnit.Case, async: true

  defp with_sm3_supported(fun) do
    if Guomi.SM3.supported?() do
      fun.()
    else
      assert true
    end
  end

  describe "hash/1" do
    test "hash_hex for abc matches official vector" do
      with_sm3_supported(fn ->
        assert Guomi.SM3.hash_hex("abc") ==
                 "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
      end)
    end

    test "binary hash is 32 bytes" do
      with_sm3_supported(fn ->
        assert byte_size(Guomi.SM3.hash("hello")) == 32
      end)
    end

    test "empty string hash" do
      with_sm3_supported(fn ->
        result = Guomi.SM3.hash_hex("")
        assert byte_size(result) == 64
      end)
    end

    test "same input produces same output" do
      with_sm3_supported(fn ->
        assert Guomi.SM3.hash_hex("test") == Guomi.SM3.hash_hex("test")
      end)
    end

    test "different inputs produce different outputs" do
      with_sm3_supported(fn ->
        assert Guomi.SM3.hash_hex("test1") != Guomi.SM3.hash_hex("test2")
      end)
    end

    test "handles binary input with null bytes" do
      with_sm3_supported(fn ->
        data = <<0, 1, 2, 3, 255, 128>>
        assert byte_size(Guomi.SM3.hash(data)) == 32
      end)
    end

    test "handles chinese characters" do
      with_sm3_supported(fn ->
        result = Guomi.SM3.hash_hex("国密算法SM3")
        assert byte_size(result) == 64
      end)
    end

    test "handles long input" do
      with_sm3_supported(fn ->
        data = String.duplicate("a", 10_000)
        assert byte_size(Guomi.SM3.hash(data)) == 32
      end)
    end
  end

  test "handles iodata input" do
    with_sm3_supported(fn ->
      iodata = ["hello", " ", "world"]
      bin = "hello world"
      assert Guomi.SM3.hash(iodata) == Guomi.SM3.hash(bin)
      assert Guomi.SM3.hash_hex(iodata) == Guomi.SM3.hash_hex(bin)
    end)
  end

  test "hash and hash_hex are consistent" do
    with_sm3_supported(fn ->
      data = "test consistency"
      assert Base.decode16!(Guomi.SM3.hash_hex(data), case: :lower) == Guomi.SM3.hash(data)
    end)
  end

  # Block boundary tests: SM3 block size = 64 bytes
  # Input sizes: 55 (max single-block w/o extra padding block),
  #              56 (min 2-block), 63, 64 (exact 1 block), 65, 128 (exact 2), 129
  for len <- [55, 56, 63, 64, 65, 128, 129] do
    @input String.duplicate("a", len)
    test "handles input of exactly #{len} bytes (block boundary)" do
      with_sm3_supported(fn ->
        assert byte_size(Guomi.SM3.hash(@input)) == 32
        assert byte_size(Guomi.SM3.hash_hex(@input)) == 64
      end)
    end
  end

  # Known answer test for empty string
  test "empty string hash matches known vector" do
    with_sm3_supported(fn ->
      # SM3("") empty string hash
      expected = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
      assert Guomi.SM3.hash_hex("") == expected
    end)
  end

  describe "hash_hex/1" do
    test "returns lowercase hex string" do
      with_sm3_supported(fn ->
        result = Guomi.SM3.hash_hex("ABC")
        assert result == String.downcase(result)
      end)
    end

    test "hex string length is 64 for any input" do
      with_sm3_supported(fn ->
        assert byte_size(Guomi.SM3.hash_hex("")) == 64
        assert byte_size(Guomi.SM3.hash_hex("a")) == 64
        assert byte_size(Guomi.SM3.hash_hex("hello world")) == 64
      end)
    end
  end

  describe "supported?/0" do
    test "returns boolean" do
      assert is_boolean(Guomi.SM3.supported?())
    end
  end
end
