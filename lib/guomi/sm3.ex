defmodule Guomi.SM3 do
  @moduledoc """
  SM3 密码杂凑算法实现。

  SM3 是中国国家密码管理局发布的密码杂凑算法标准（GM/T 0004-2012），
  输出 256 位（32 字节）的哈希值。

  ## 使用示例

      iex> Guomi.SM3.hash("hello")
      <<...>>

      iex> Guomi.SM3.hash_hex("hello")
      "..."

  """

  @doc """
  计算 SM3 哈希值，返回二进制。

  ## 参数

    - data: 输入数据（二进制或字符串）

  """
  def hash(data) when is_binary(data) do
    :crypto.hash(:sm3, data)
  end

  @doc """
  计算 SM3 哈希值，返回十六进制字符串。

  ## 参数

    - data: 输入数据（二进制或字符串）

  """
  def hash_hex(data) when is_binary(data) do
    data
    |> hash()
    |> Base.encode16(case: :lower)
  end
end
