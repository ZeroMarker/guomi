defmodule GuomiTest do
  use ExUnit.Case, async: true

  doctest Guomi
  doctest Guomi.SM3

  describe "algorithms/0" do
    test "lists exported algorithms" do
      assert Guomi.algorithms() == [:sm2, :sm3, :sm4]
    end
  end

  describe "supported/0" do
    test "returns runtime support map" do
      assert %{
               sm2: sm2?,
               sm3: sm3?,
               sm4: sm4?
             } = Guomi.supported()

      assert is_boolean(sm2?)
      assert is_boolean(sm3?)
      assert is_boolean(sm4?)
    end
  end
end
