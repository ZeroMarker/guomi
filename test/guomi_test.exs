defmodule GuomiTest do
  use ExUnit.Case
  doctest Guomi

  describe "SM3 哈希算法" do
    test "hash 返回 32 字节二进制哈希值" do
      result = Guomi.SM3.hash("abc")
      assert byte_size(result) == 32
    end

    test "hash_hex 返回正确的十六进制字符串" do
      # 使用 Erlang crypto 的 SM3 测试结果
      assert Guomi.SM3.hash_hex("abc") == 
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    end

    test "空字符串哈希" do
      result = Guomi.SM3.hash_hex("")
      assert byte_size(result) == 64
    end

    test "长字符串哈希" do
      data = String.duplicate("a", 1000)
      result = Guomi.SM3.hash_hex(data)
      assert byte_size(result) == 64
    end

    test "相同输入产生相同输出" do
      hash1 = Guomi.SM3.hash_hex("test")
      hash2 = Guomi.SM3.hash_hex("test")
      assert hash1 == hash2
    end

    test "二进制数据哈希" do
      data = <<0, 1, 2, 3, 255, 128, 64, 32, 16, 8, 4, 2, 1, 0>>
      result = Guomi.SM3.hash(data)
      assert byte_size(result) == 32
    end

    test "中文字符串哈希" do
      data = "国密算法SM3"
      result = Guomi.SM3.hash_hex(data)
      assert byte_size(result) == 64
    end

    test "特殊字符哈希" do
      data = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
      result = Guomi.SM3.hash_hex(data)
      assert byte_size(result) == 64
    end

    test "哈希碰撞检测 - 不同输入不同输出" do
      hash1 = Guomi.SM3.hash_hex("test1")
      hash2 = Guomi.SM3.hash_hex("test2")
      assert hash1 != hash2
    end
  end

  describe "SM4 加密解密" do
    setup do
      key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      {:ok, key: key}
    end

    test "加密和解密互为逆运算", %{key: key} do
      plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      {:ok, ciphertext} = Guomi.SM4.encrypt(plaintext, key)
      {:ok, decrypted} = Guomi.SM4.decrypt(ciphertext, key)
      assert decrypted == plaintext
    end

    test "密钥长度校验" do
      short_key = <<1, 2, 3>>
      plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      assert {:error, "密钥长度必须为 16 字节"} = Guomi.SM4.encrypt(plaintext, short_key)
    end

    test "明文长度校验" do
      key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      plaintext = <<0, 1, 2, 3>>
      assert {:error, "明文长度必须是 16 字节的倍数"} = Guomi.SM4.encrypt(plaintext, key)
    end

    test "多块加密解密", %{key: key} do
      plaintext = String.duplicate("0123456789ABCDEF", 10)
      {:ok, ciphertext} = Guomi.SM4.encrypt(plaintext, key)
      {:ok, decrypted} = Guomi.SM4.decrypt(ciphertext, key)
      assert decrypted == plaintext
    end

    test "CBC 模式加密解密" do
      key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      iv = <<16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1>>
      plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      
      {:ok, ciphertext} = Guomi.SM4.encrypt_cbc(plaintext, key, iv)
      {:ok, decrypted} = Guomi.SM4.decrypt_cbc(ciphertext, key, iv)
      assert decrypted == plaintext
    end

    test "CBC 模式 IV 长度校验" do
      key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      short_iv = <<1, 2, 3>>
      plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      
      assert {:error, "IV 长度必须为 16 字节"} = Guomi.SM4.encrypt_cbc(plaintext, key, short_iv)
    end

    test "CBC 模式解密 IV 长度校验" do
      key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      short_iv = <<1, 2, 3>>
      ciphertext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      
      assert {:error, "IV 长度必须为 16 字节"} = Guomi.SM4.decrypt_cbc(ciphertext, key, short_iv)
    end

    test "CBC 模式多块加密解密", %{key: key} do
      iv = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      plaintext = String.duplicate("0123456789ABCDEF", 10)
      {:ok, ciphertext} = Guomi.SM4.encrypt_cbc(plaintext, key, iv)
      {:ok, decrypted} = Guomi.SM4.decrypt_cbc(ciphertext, key, iv)
      assert decrypted == plaintext
    end

    test "全零密钥加密解密" do
      key = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
      plaintext = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
      {:ok, ciphertext} = Guomi.SM4.encrypt(plaintext, key)
      {:ok, decrypted} = Guomi.SM4.decrypt(ciphertext, key)
      assert decrypted == plaintext
    end

    test "全F密钥加密解密" do
      key = <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255>>
      plaintext = <<15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0>>
      {:ok, ciphertext} = Guomi.SM4.encrypt(plaintext, key)
      {:ok, decrypted} = Guomi.SM4.decrypt(ciphertext, key)
      assert decrypted == plaintext
    end

    test "密文长度校验" do
      key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      short_ciphertext = <<0, 1, 2, 3>>
      assert {:error, "密文长度必须是 16 字节的倍数"} = Guomi.SM4.decrypt(short_ciphertext, key)
    end
  end

  describe "SM2 签名验签" do
    setup do
      {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      {:ok, priv: priv, pub: pub}
    end

    test "生成密钥对", %{priv: priv, pub: pub} do
      assert byte_size(priv) == 32
      assert byte_size(pub) == 65
      assert :binary.first(pub) == 0x04
    end

    test "签名和验签", %{priv: priv, pub: pub} do
      message = "Hello SM2!"
      {:ok, signature} = Guomi.SM2.sign(message, priv)
      {:ok, result} = Guomi.SM2.verify(message, signature, pub)
      assert result == true
    end

    test "验签失败 - 消息被篡改", %{priv: priv, pub: pub} do
      message = "Hello SM2!"
      tampered = "Tampered!"
      {:ok, signature} = Guomi.SM2.sign(message, priv)
      {:ok, result} = Guomi.SM2.verify(tampered, signature, pub)
      assert result == false
    end

    test "签名长度为 64 字节", %{priv: _priv, pub: _pub} do
      {:ok, priv, _pub} = Guomi.SM2.generate_keypair()
      message = "Test message"
      {:ok, signature} = Guomi.SM2.sign(message, priv)
      assert byte_size(signature) == 64
    end

    test "验签失败 - 使用错误公钥" do
      {:ok, _priv1, pub1} = Guomi.SM2.generate_keypair()
      {:ok, priv2, _pub2} = Guomi.SM2.generate_keypair()
      message = "Hello SM2!"
      {:ok, signature} = Guomi.SM2.sign(message, priv2)
      # 使用错误公钥验签应该失败
      {:ok, result} = Guomi.SM2.verify(message, signature, pub1)
      assert result == false
    end

    test "验签失败 - 签名被篡改" do
      {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      message = "Hello SM2!"
      {:ok, signature} = Guomi.SM2.sign(message, priv)
      # 篡改签名的最后一个字节
      <<head::binary-size(63), _last::binary>> = signature
      tampered_signature = head <> <<0xFF>>
      {:ok, result} = Guomi.SM2.verify(message, tampered_signature, pub)
      assert result == false
    end

    test "空消息签名验签" do
      {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      message = ""
      {:ok, signature} = Guomi.SM2.sign(message, priv)
      {:ok, result} = Guomi.SM2.verify(message, signature, pub)
      assert result == true
    end

    test "不同 user_id 验签失败" do
      {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      message = "Hello SM2!"
      user_id1 = "user_id_1"
      user_id2 = "user_id_2"
      {:ok, signature} = Guomi.SM2.sign(message, priv, user_id1)
      # 使用不同 user_id 验签应该失败
      {:ok, result} = Guomi.SM2.verify(message, signature, pub, user_id2)
      assert result == false
    end

    test "二进制消息签名验签" do
      {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      # 使用二进制消息（包含 null 字节）
      message = <<0, 1, 2, 3, 0, 255, 128>>
      {:ok, signature} = Guomi.SM2.sign(message, priv)
      {:ok, result} = Guomi.SM2.verify(message, signature, pub)
      assert result == true
    end
  end

  describe "SM2 加密解密" do
    setup do
      {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      {:ok, priv: priv, pub: pub}
    end

    test "加密和解密互为逆运算", %{priv: priv, pub: pub} do
      plaintext = "Secret message!"
      {:ok, ciphertext} = Guomi.SM2.encrypt(plaintext, pub)
      {:ok, decrypted} = Guomi.SM2.decrypt(ciphertext, priv)
      assert decrypted == plaintext
    end

    test "密文长度大于明文", %{priv: _priv, pub: pub} do
      plaintext = "Short"
      {:ok, ciphertext} = Guomi.SM2.encrypt(plaintext, pub)
      assert byte_size(ciphertext) > byte_size(plaintext)
    end

    test "解密失败 - 使用错误私钥" do
      {:ok, _priv1, pub1} = Guomi.SM2.generate_keypair()
      {:ok, priv2, _pub2} = Guomi.SM2.generate_keypair()
      plaintext = "Secret message!"
      {:ok, ciphertext} = Guomi.SM2.encrypt(plaintext, pub1)
      # 使用错误私钥解密应该失败
      result = Guomi.SM2.decrypt(ciphertext, priv2)
      assert match?({:error, _}, result)
    end

    test "解密失败 - 密文被篡改" do
      {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      plaintext = "Secret message!"
      {:ok, ciphertext} = Guomi.SM2.encrypt(plaintext, pub)
      # 篡改密文
      <<head::binary-size(10), _rest::binary>> = ciphertext
      tampered = head <> <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>> <> <<"tampered">>
      result = Guomi.SM2.decrypt(tampered, priv)
      assert match?({:error, _}, result)
    end

    test "解密失败 - 密文长度过短" do
      {:ok, priv, _pub} = Guomi.SM2.generate_keypair()
      short_ciphertext = <<1, 2, 3, 4, 5>>
      result = Guomi.SM2.decrypt(short_ciphertext, priv)
      assert {:error, "密文长度无效"} = result
    end

    test "长消息加密解密", %{priv: priv, pub: pub} do
      # 测试较长消息的加密解密
      plaintext = String.duplicate("国密算法测试数据-", 100)
      {:ok, ciphertext} = Guomi.SM2.encrypt(plaintext, pub)
      {:ok, decrypted} = Guomi.SM2.decrypt(ciphertext, priv)
      assert decrypted == plaintext
    end

    test "二进制数据加密解密", %{priv: priv, pub: pub} do
      # 测试二进制数据的加密解密
      plaintext = <<0, 1, 2, 3, 4, 5, 255, 128, 64, 32, 16, 8, 4, 2, 1, 0>>
      {:ok, ciphertext} = Guomi.SM2.encrypt(plaintext, pub)
      {:ok, decrypted} = Guomi.SM2.decrypt(ciphertext, priv)
      assert decrypted == plaintext
    end

    test "加密结果一致性 - 相同明文不同密文", %{priv: priv, pub: pub} do
      # 由于每次加密使用随机 k，相同明文应该产生不同密文
      plaintext = "Test message"
      {:ok, ciphertext1} = Guomi.SM2.encrypt(plaintext, pub)
      {:ok, ciphertext2} = Guomi.SM2.encrypt(plaintext, pub)
      # 两次加密产生的密文不同（因为随机 k）
      assert ciphertext1 != ciphertext2
      # 但解密后应该相同
      {:ok, decrypted1} = Guomi.SM2.decrypt(ciphertext1, priv)
      {:ok, decrypted2} = Guomi.SM2.decrypt(ciphertext2, priv)
      assert decrypted1 == plaintext
      assert decrypted2 == plaintext
    end
  end
end
