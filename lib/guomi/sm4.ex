defmodule Guomi.SM4 do
  @moduledoc """
  SM4 分组密码算法实现。

  SM4 是中国国家密码管理局发布的分组密码算法标准（GM/T 0002-2012），
  分组长度为 128 位，密钥长度为 128 位。

  ## 使用示例

      iex> {:ok, ciphertext} = Guomi.SM4.encrypt(plaintext, key)
      iex> {:ok, plaintext} = Guomi.SM4.decrypt(ciphertext, key)

  """

  @doc """
  SM4 加密（ECB 模式）。

  ## 参数

    - plaintext: 明文（必须是 16 字节的倍数）
    - key: 密钥（16 字节）

  ## 返回

    - `{:ok, ciphertext}` - 加密成功
    - `{:error, reason}` - 加密失败

  """
  def encrypt(plaintext, key) when is_binary(plaintext) and is_binary(key) do
    cond do
      byte_size(key) != 16 ->
        {:error, "密钥长度必须为 16 字节"}

      rem(byte_size(plaintext), 16) != 0 ->
        {:error, "明文长度必须是 16 字节的倍数"}

      true ->
        ciphertext = :crypto.crypto_one_time(:sm4_ecb, key, plaintext, true)
        {:ok, ciphertext}
    end
  end

  @doc """
  SM4 解密（ECB 模式）。

  ## 参数

    - ciphertext: 密文（必须是 16 字节的倍数）
    - key: 密钥（16 字节）

  ## 返回

    - `{:ok, plaintext}` - 解密成功
    - `{:error, reason}` - 解密失败

  """
  def decrypt(ciphertext, key) when is_binary(ciphertext) and is_binary(key) do
    cond do
      byte_size(key) != 16 ->
        {:error, "密钥长度必须为 16 字节"}

      rem(byte_size(ciphertext), 16) != 0 ->
        {:error, "密文长度必须是 16 字节的倍数"}

      true ->
        plaintext = :crypto.crypto_one_time(:sm4_ecb, key, ciphertext, false)
        {:ok, plaintext}
    end
  end

  @doc """
  SM4 加密（CBC 模式）。

  ## 参数

    - plaintext: 明文（必须是 16 字节的倍数）
    - key: 密钥（16 字节）
    - iv: 初始化向量（16 字节）

  ## 返回

    - `{:ok, ciphertext}` - 加密成功
    - `{:error, reason}` - 加密失败

  """
  def encrypt_cbc(plaintext, key, iv) when is_binary(plaintext) and is_binary(key) and is_binary(iv) do
    cond do
      byte_size(key) != 16 ->
        {:error, "密钥长度必须为 16 字节"}

      byte_size(iv) != 16 ->
        {:error, "IV 长度必须为 16 字节"}

      rem(byte_size(plaintext), 16) != 0 ->
        {:error, "明文长度必须是 16 字节的倍数"}

      true ->
        ciphertext = :crypto.crypto_one_time(:sm4_cbc, key, iv, plaintext, true)
        {:ok, ciphertext}
    end
  end

  @doc """
  SM4 解密（CBC 模式）。

  ## 参数

    - ciphertext: 密文（必须是 16 字节的倍数）
    - key: 密钥（16 字节）
    - iv: 初始化向量（16 字节）

  ## 返回

    - `{:ok, plaintext}` - 解密成功
    - `{:error, reason}` - 解密失败

  """
  def decrypt_cbc(ciphertext, key, iv) when is_binary(ciphertext) and is_binary(key) and is_binary(iv) do
    cond do
      byte_size(key) != 16 ->
        {:error, "密钥长度必须为 16 字节"}

      byte_size(iv) != 16 ->
        {:error, "IV 长度必须为 16 字节"}

      rem(byte_size(ciphertext), 16) != 0 ->
        {:error, "密文长度必须是 16 字节的倍数"}

      true ->
        plaintext = :crypto.crypto_one_time(:sm4_cbc, key, iv, ciphertext, false)
        {:ok, plaintext}
    end
  end
end
