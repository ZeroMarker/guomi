defmodule Guomi do
  @moduledoc """
  国密算法 Elixir 实现。

  本库实现了中国国家密码管理局发布的密码算法标准：

  - **SM2** - 椭圆曲线公钥密码算法（签名、验签、加密、解密）
  - **SM3** - 密码杂凑算法
  - **SM4** - 分组密码算法

  ## 使用示例

  ### SM3 哈希

      iex> hash = Guomi.SM3.hash_hex("hello")
      iex> byte_size(hash)
      64

  ### SM4 加密解密

      iex> key = :crypto.strong_rand_bytes(16)
      iex> plaintext = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>
      iex> {:ok, ciphertext} = Guomi.SM4.encrypt(plaintext, key)
      iex> {:ok, ^plaintext} = Guomi.SM4.decrypt(ciphertext, key)

  ### SM2 签名验签

      iex> {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      iex> {:ok, sig} = Guomi.SM2.sign("message", priv)
      iex> {:ok, true} = Guomi.SM2.verify("message", sig, pub)

  """
end
