defmodule Guomi.CLI do
  @moduledoc """
  Command-line interface for Guomi cryptographic tools.

  ## Usage

      mix escript.build
      ./guomi <command> [options]

  ## Commands

  - `sm3` - Compute SM3 hash
  - `sm4` - SM4 encryption/decryption
  - `sm2` - SM2 key generation, sign/verify, encrypt/decrypt
  - `version` - Show version information
  - `help` - Show help message
  """

  @version Mix.Project.config()[:version]

  def main(args) do
    try do
      run(args)
    rescue
      e ->
        IO.puts(:stderr, "Error: #{Exception.message(e)}")
        System.halt(1)
    end
  end

  def run([]) do
    print_help()
  end

  def run(["help" | _]) do
    print_help()
  end

  def run(["version" | _]) do
    IO.puts("guomi v#{@version}")
  end

  def run(["sm3" | args]) do
    handle_sm3(args)
  end

  def run(["sm4" | args]) do
    handle_sm4(args)
  end

  def run(["sm2" | args]) do
    handle_sm2(args)
  end

  def run([command | _]) do
    IO.puts(:stderr, "Unknown command: #{command}")
    IO.puts(:stderr, "Run 'guomi help' for usage information.")
    System.halt(1)
  end

  # SM3 command handlers
  defp handle_sm3([]) do
    # Read from stdin
    input = IO.read(:stdio, :eof)
    hash = Guomi.SM3.hash_hex(input)
    IO.puts(hash)
  end

  defp handle_sm3(args) do
    {opts, remaining, _} = OptionParser.parse(args, strict: [hex: :boolean, help: :boolean])

    if opts[:help] do
      print_sm3_help()
    else
      # Treat remaining args as input (file or string)
      input =
        case remaining do
          [file] when file in ["-", "--"] ->
            IO.read(:stdio, :eof)

          [file] ->
            File.read!(file)

          [] ->
            IO.read(:stdio, :eof)

          _ ->
            Enum.join(remaining, " ")
        end

      if opts[:hex] do
        hash = Guomi.SM3.hash_hex(input)
        IO.puts(hash)
      else
        hash = Guomi.SM3.hash(input)
        IO.write(hash)
      end
    end
  end

  # SM4 command handlers
  defp handle_sm4([]) do
    print_sm4_help()
  end

  defp handle_sm4(args) do
    {opts, remaining, _} =
      OptionParser.parse(args,
        strict: [
          mode: :string,
          key: :string,
          iv: :string,
          decrypt: :boolean,
          hex: :boolean,
          padding: :string,
          help: :boolean
        ]
      )

    if opts[:help] do
      print_sm4_help()
    else
      mode = Keyword.get(opts, :mode, "ecb")
      key = parse_hex_or_exit(opts[:key], "key")
      padding = Keyword.get(opts, :padding, "pkcs7") |> String.to_atom()

      input =
        case remaining do
          [] -> IO.read(:stdio, :eof)
          [file] when file in ["-", "--"] -> IO.read(:stdio, :eof)
          [file] -> File.read!(file)
          _ -> Enum.join(remaining, " ")
        end

      result =
        if opts[:decrypt] do
          decrypt_sm4(input, key, mode, opts[:iv], padding, opts[:hex])
        else
          encrypt_sm4(input, key, mode, opts[:iv], padding)
        end

      case result do
        {:ok, output} ->
          if opts[:hex] do
            IO.puts(Base.encode16(output, case: :lower))
          else
            IO.write(output)
          end

        {:error, reason} ->
          IO.puts(:stderr, "Error: #{format_sm4_error(reason)}")
          System.halt(1)
      end
    end
  end

  defp encrypt_sm4(input, key, "ecb", _iv, padding) do
    Guomi.SM4.encrypt(input, key, padding: padding)
  end

  defp encrypt_sm4(input, key, "cbc", iv, padding) do
    iv = parse_hex_or_exit(iv, "iv")
    Guomi.SM4.encrypt_cbc(input, key, iv, padding: padding)
  end

  defp encrypt_sm4(_input, _key, mode, _iv, _padding) do
    {:error, {:invalid_mode, mode}}
  end

  defp decrypt_sm4(input, key, "ecb", _iv, padding, hex_input) do
    ciphertext = if hex_input, do: Base.decode16!(input, case: :mixed), else: input
    Guomi.SM4.decrypt(ciphertext, key, padding: padding)
  end

  defp decrypt_sm4(input, key, "cbc", iv, padding, hex_input) do
    ciphertext = if hex_input, do: Base.decode16!(input, case: :mixed), else: input
    iv = parse_hex_or_exit(iv, "iv")
    Guomi.SM4.decrypt_cbc(ciphertext, key, iv, padding: padding)
  end

  defp decrypt_sm4(_input, _key, mode, _iv, _padding, _hex) do
    {:error, {:invalid_mode, mode}}
  end

  # SM2 command handlers
  defp handle_sm2([]) do
    print_sm2_help()
  end

  defp handle_sm2(args) do
    {opts, remaining, _} =
      OptionParser.parse(args,
        strict: [
          generate: :boolean,
          sign: :boolean,
          verify: :boolean,
          encrypt: :boolean,
          decrypt: :boolean,
          public_key: :string,
          private_key: :string,
          message: :string,
          signature: :string,
          ciphertext: :string,
          hex: :boolean,
          help: :boolean
        ]
      )

    if opts[:help] do
      print_sm2_help()
    else
      cond do
        opts[:generate] ->
          do_generate_keypair()

        opts[:sign] ->
          do_sign(remaining, opts)

        opts[:verify] ->
          do_verify(remaining, opts)

        opts[:encrypt] ->
          do_encrypt(remaining, opts)

        opts[:decrypt] ->
          do_decrypt(remaining, opts)

        true ->
          print_sm2_help()
      end
    end
  end

  defp do_generate_keypair do
    case Guomi.SM2.generate_keypair() do
      {:ok, private_key, public_key} ->
        IO.puts("Private Key:")
        IO.puts(Base.encode16(private_key, case: :lower))
        IO.puts("Public Key:")
        IO.puts(Base.encode16(public_key, case: :lower))

      {:error, :unsupported} ->
        IO.puts(:stderr, "Error: SM2 is not supported on this system.")
        IO.puts(:stderr, "Please ensure OpenSSL 3.0+ with SM2 support is installed.")
        System.halt(1)
    end
  end

  defp do_sign(args, opts) do
    message = get_message(args, opts)
    private_key = parse_hex_or_exit(opts[:private_key], "private-key")

    case Guomi.SM2.sign(message, private_key) do
      {:ok, signature} ->
        IO.puts(Base.encode16(signature, case: :lower))

      {:error, :unsupported} ->
        IO.puts(:stderr, "Error: SM2 signing is not supported on this system.")
        System.halt(1)
    end
  end

  defp do_verify(args, opts) do
    message = get_message(args, opts)
    signature = parse_hex_or_exit(opts[:signature], "signature")
    public_key = parse_hex_or_exit(opts[:public_key], "public-key")

    case Guomi.SM2.verify(message, signature, public_key) do
      {:ok, true} ->
        IO.puts("Signature is valid.")
        System.halt(0)

      {:ok, false} ->
        IO.puts("Signature is INVALID.")
        System.halt(1)

      {:error, :unsupported} ->
        IO.puts(:stderr, "Error: SM2 verification is not supported on this system.")
        System.halt(1)
    end
  end

  defp do_encrypt(args, opts) do
    message = get_message(args, opts)
    public_key = parse_hex_or_exit(opts[:public_key], "public-key")

    case Guomi.SM2.encrypt(message, public_key) do
      {:ok, ciphertext} ->
        IO.puts(Base.encode16(ciphertext, case: :lower))

      {:error, reason} ->
        IO.puts(:stderr, "Error: #{format_sm2_error(reason)}")
        System.halt(1)
    end
  end

  defp do_decrypt(args, opts) do
    ciphertext =
      case {opts[:ciphertext], args} do
        {nil, [file]} when file not in ["-", "--"] ->
          File.read!(file)

        {ciph, _} when is_binary(ciph) ->
          ciph

        _ ->
          IO.read(:stdio, :eof)
      end

    ciphertext = Base.decode16!(ciphertext, case: :mixed)
    private_key = parse_hex_or_exit(opts[:private_key], "private-key")

    case Guomi.SM2.decrypt(ciphertext, private_key) do
      {:ok, plaintext} ->
        IO.write(plaintext)

      {:error, reason} ->
        IO.puts(:stderr, "Error: #{format_sm2_error(reason)}")
        System.halt(1)
    end
  end

  defp get_message(args, opts) do
    case {opts[:message], args} do
      {nil, [file]} when file not in ["-", "--"] ->
        File.read!(file)

      {msg, _} when is_binary(msg) ->
        msg

      _ ->
        IO.read(:stdio, :eof)
    end
  end

  defp parse_hex_or_exit(nil, _), do: nil

  defp parse_hex_or_exit(hex_string, name) do
    case Base.decode16(hex_string, case: :mixed) do
      {:ok, binary} ->
        binary

      :error ->
        IO.puts(:stderr, "Error: Invalid hex encoding for #{name}")
        System.halt(1)
    end
  end

  defp format_sm4_error(:invalid_key_size), do: "Invalid key size (must be 16 bytes)"
  defp format_sm4_error(:invalid_iv_size), do: "Invalid IV size (must be 16 bytes)"
  defp format_sm4_error(:invalid_block_size), do: "Invalid block size"
  defp format_sm4_error(:invalid_padding), do: "Invalid padding option"
  defp format_sm4_error(:unsupported), do: "SM4 is not supported on this system"
  defp format_sm4_error({:invalid_mode, mode}), do: "Invalid mode: #{mode} (use 'ecb' or 'cbc')"
  defp format_sm4_error(_), do: "Unknown error"

  defp format_sm2_error(:unsupported), do: "SM2 is not supported on this system"
  defp format_sm2_error(:decryption_failed), do: "Decryption failed"
  defp format_sm2_error(:invalid_ciphertext), do: "Invalid ciphertext"
  defp format_sm2_error(_), do: "Unknown error"

  # Help messages
  defp print_help do
    IO.puts("""
    guomi v#{@version} - Chinese Commercial Cryptographic Algorithms CLI

    USAGE:
        guomi <command> [options]

    COMMANDS:
        sm3         Compute SM3 hash
        sm4         SM4 encryption/decryption
        sm2         SM2 key generation, sign/verify, encrypt/decrypt
        version     Show version information
        help        Show this help message

    Run 'guomi <command> --help' for more information on a command.

    EXAMPLES:
        # SM3 hash
        echo -n "hello" | guomi sm3
        guomi sm3 --hex file.txt

        # SM4 encryption
        echo "secret" | guomi sm4 --key 0123456789abcdef0123456789abcdef
        guomi sm4 --decrypt --hex --key 0123456789abcdef0123456789abcdef < ciphertext.bin

        # SM2 key generation
        guomi sm2 --generate

        # SM2 sign
        echo "message" | guomi sm2 --sign --private-key <hex-key>

        # SM2 verify
        guomi sm2 --verify --public-key <hex-key> --signature <hex-sig> message.txt
    """)
  end

  defp print_sm3_help do
    IO.puts("""
    guomi sm3 - Compute SM3 hash

    USAGE:
        guomi sm3 [options] [input]

    OPTIONS:
        --hex         Output hash as hexadecimal (default: binary)
        --help        Show this help message

    INPUT:
        If no input is specified, reads from stdin.
        If a file path is provided, reads from the file.
        Otherwise, treats arguments as the message.

    EXAMPLES:
        echo -n "hello" | guomi sm3
        guomi sm3 --hex "hello world"
        guomi sm3 --hex file.txt
    """)
  end

  defp print_sm4_help do
    IO.puts("""
    guomi sm4 - SM4 encryption/decryption

    USAGE:
        guomi sm4 [options] [input]

    OPTIONS:
        --mode <mode>     Encryption mode: ecb (default) or cbc
        --key <hex>       Encryption key (16 bytes hex, required)
        --iv <hex>        Initialization vector (16 bytes hex, required for CBC)
        --decrypt         Decrypt instead of encrypt
        --hex             Input/output as hexadecimal
        --padding <pad>   Padding: pkcs7 (default) or none
        --help            Show this help message

    INPUT:
        If no input is specified, reads from stdin.
        If a file path is provided, reads from the file.

    EXAMPLES:
        # Encrypt with ECB
        echo "secret" | guomi sm4 --key 0123456789abcdef0123456789abcdef

        # Encrypt with CBC
        echo "secret" | guomi sm4 --mode cbc --key 0123456789abcdef0123456789abcdef --iv 00000000000000000000000000000000

        # Decrypt (output as hex)
        guomi sm4 --decrypt --hex --key 0123456789abcdef0123456789abcdef < ciphertext.bin

        # Decrypt CBC mode
        guomi sm4 --decrypt --mode cbc --key 0123456789abcdef0123456789abcdef --iv 00000000000000000000000000000000 < ciphertext.bin
    """)
  end

  defp print_sm2_help do
    IO.puts("""
    guomi sm2 - SM2 key generation, sign/verify, encrypt/decrypt

    USAGE:
        guomi sm2 [options] [input]

    OPTIONS:
        --generate        Generate a new keypair
        --sign            Sign a message
        --verify          Verify a signature
        --encrypt         Encrypt a message
        --decrypt         Decrypt a ciphertext
        --public-key <hex>  Public key (hex encoded)
        --private-key <hex> Private key (hex encoded)
        --message <msg>     Message to sign/verify/encrypt
        --signature <hex>   Signature to verify (hex encoded)
        --ciphertext <hex>  Ciphertext to decrypt (hex encoded)
        --hex             Output as hexadecimal
        --help            Show this help message

    INPUT:
        If no input is specified, reads from stdin.
        If a file path is provided, reads from the file.

    EXAMPLES:
        # Generate keypair
        guomi sm2 --generate

        # Sign a message
        echo "message" | guomi sm2 --sign --private-key <hex-key>

        # Verify a signature
        guomi sm2 --verify --public-key <hex-key> --signature <hex-sig> message.txt

        # Encrypt a message
        echo "secret" | guomi sm2 --encrypt --public-key <hex-key>

        # Decrypt a ciphertext
        guomi sm2 --decrypt --private-key <hex-key> --ciphertext <hex-cipher>
    """)
  end
end
