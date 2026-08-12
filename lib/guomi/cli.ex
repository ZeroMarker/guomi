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

  @doc "Runs the escript entry point and converts unhandled errors to exit status 1."
  @spec main([String.t()]) :: no_return() | :ok
  def main(args) do
    run(args)
  rescue
    e ->
      IO.puts(:stderr, "Error: #{Exception.message(e)}")
      System.halt(1)
  end

  @doc "Dispatches parsed command-line arguments. Primarily exposed for integration tests."
  @spec run([String.t()]) :: no_return() | :ok
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
    fail(["Unknown command: #{command}", "Run 'guomi help' for usage information."])
  end

  # SM3 command handlers
  defp handle_sm3([]) do
    ensure_sm3_supported!()
    input = read_input([])
    hash = Guomi.SM3.hash_hex(input)
    IO.puts(hash)
  end

  defp handle_sm3(args) do
    {opts, remaining, invalid} =
      OptionParser.parse(args, strict: [hex: :boolean, file: :string, help: :boolean])

    if invalid != [] do
      fail("Unknown or invalid SM3 option: #{format_invalid_options(invalid)}")
    else
      handle_parsed_sm3(opts, remaining)
    end
  end

  defp handle_parsed_sm3(opts, remaining) do
    if opts[:help] do
      print_sm3_help()
    else
      ensure_sm3_supported!()
      input = read_input(remaining, opts)

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
    {opts, remaining, invalid} =
      OptionParser.parse(args,
        strict: [
          mode: :string,
          key: :string,
          iv: :string,
          counter: :string,
          decrypt: :boolean,
          hex: :boolean,
          input_hex: :boolean,
          output_hex: :boolean,
          padding: :string,
          file: :string,
          help: :boolean
        ]
      )

    if invalid != [] do
      fail("Unknown or invalid SM4 option: #{format_invalid_options(invalid)}")
    else
      handle_parsed_sm4(opts, remaining)
    end
  end

  defp handle_parsed_sm4(opts, remaining) do
    if opts[:help] do
      print_sm4_help()
    else
      mode = Keyword.get(opts, :mode, "ecb")
      key = required_hex_or_exit(opts[:key], "key")
      iv_or_counter = validate_sm4_parameter(mode, opts)
      padding = parse_sm4_padding(mode, opts)
      decrypt? = Keyword.get(opts, :decrypt, false)
      hex? = Keyword.get(opts, :hex, false)
      input_hex? = sm4_input_hex?(opts, hex?, decrypt?)
      output_hex? = sm4_output_hex?(opts, hex?, decrypt?)
      input = read_input(remaining, opts)

      result =
        if decrypt? do
          decrypt_sm4(input, key, mode, iv_or_counter, padding, input_hex?)
        else
          encrypt_sm4(input, key, mode, iv_or_counter, padding, input_hex?)
        end

      case result do
        {:ok, output} ->
          write_output(output, output_hex?)

        {:error, reason} ->
          fail(format_sm4_error(reason))
      end
    end
  end

  defp encrypt_sm4(input, key, "ecb", _iv, padding, input_hex?) do
    input = if input_hex?, do: parse_hex_or_exit(input, "plaintext"), else: input
    Guomi.SM4.encrypt(input, key, padding: padding)
  end

  defp encrypt_sm4(input, key, "cbc", iv, padding, input_hex?) do
    input = if input_hex?, do: parse_hex_or_exit(input, "plaintext"), else: input
    Guomi.SM4.encrypt_cbc(input, key, iv, padding: padding)
  end

  defp encrypt_sm4(input, key, "ctr", counter, :none, input_hex?) do
    input = if input_hex?, do: parse_hex_or_exit(input, "plaintext"), else: input
    Guomi.SM4.encrypt_ctr(input, key, counter)
  end

  defp encrypt_sm4(_input, _key, mode, _iv, _padding, _input_hex?) do
    {:error, {:invalid_mode, mode}}
  end

  defp decrypt_sm4(input, key, "ecb", _iv, padding, hex_input) do
    ciphertext = if hex_input, do: parse_hex_or_exit(input, "ciphertext"), else: input
    Guomi.SM4.decrypt(ciphertext, key, padding: padding)
  end

  defp decrypt_sm4(input, key, "cbc", iv, padding, hex_input) do
    ciphertext = if hex_input, do: parse_hex_or_exit(input, "ciphertext"), else: input
    Guomi.SM4.decrypt_cbc(ciphertext, key, iv, padding: padding)
  end

  defp decrypt_sm4(input, key, "ctr", counter, :none, hex_input) do
    ciphertext = if hex_input, do: parse_hex_or_exit(input, "ciphertext"), else: input
    Guomi.SM4.decrypt_ctr(ciphertext, key, counter)
  end

  defp decrypt_sm4(_input, _key, mode, _iv, _padding, _hex) do
    {:error, {:invalid_mode, mode}}
  end

  # SM2 command handlers
  defp handle_sm2([]) do
    print_sm2_help()
  end

  defp handle_sm2(args) do
    {opts, remaining, invalid} =
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
          file: :string,
          signature: :string,
          ciphertext: :string,
          help: :boolean
        ]
      )

    if invalid != [] do
      fail("Unknown or invalid SM2 option: #{format_invalid_options(invalid)}")
    else
      handle_parsed_sm2(opts, remaining)
    end
  end

  defp handle_parsed_sm2(opts, remaining) do
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
    end
  end

  defp do_sign(args, opts) do
    message = get_message(args, opts)
    private_key = required_hex_or_exit(opts[:private_key], "private-key")

    case Guomi.SM2.sign(message, private_key) do
      {:ok, signature} ->
        IO.puts(Base.encode16(signature, case: :lower))

      {:error, :unsupported} ->
        fail("SM2 signing is not supported on this system.")

      {:error, reason} ->
        fail(format_sm2_error(reason))
    end
  end

  defp do_verify(args, opts) do
    message = get_message(args, opts)
    signature = required_hex_or_exit(opts[:signature], "signature")
    public_key = required_hex_or_exit(opts[:public_key], "public-key")

    case Guomi.SM2.verify(message, signature, public_key) do
      {:ok, true} ->
        IO.puts("Signature is valid.")
        System.halt(0)

      {:ok, false} ->
        IO.puts("Signature is INVALID.")
        System.halt(1)

      {:error, :unsupported} ->
        fail("SM2 verification is not supported on this system.")

      {:error, reason} ->
        fail(format_sm2_error(reason))
    end
  end

  defp do_encrypt(args, opts) do
    message = get_message(args, opts)
    public_key = required_hex_or_exit(opts[:public_key], "public-key")

    case Guomi.SM2.encrypt(message, public_key) do
      {:ok, ciphertext} ->
        IO.puts(Base.encode16(ciphertext, case: :lower))

      {:error, reason} ->
        fail(format_sm2_error(reason))
    end
  end

  defp do_decrypt(args, opts) do
    ciphertext =
      case {opts[:ciphertext], opts[:file], args} do
        {ciph, _file, _args} when is_binary(ciph) ->
          ciph

        {nil, nil, []} ->
          required_hex_or_exit(nil, "ciphertext")

        {nil, _file, _args} ->
          read_input(args, opts)
      end

    ciphertext = parse_hex_or_exit(ciphertext, "ciphertext")
    private_key = required_hex_or_exit(opts[:private_key], "private-key")

    case Guomi.SM2.decrypt(ciphertext, private_key) do
      {:ok, plaintext} ->
        IO.write(plaintext)

      {:error, reason} ->
        fail(format_sm2_error(reason))
    end
  end

  defp get_message(args, opts) do
    case {opts[:message], args} do
      {msg, _} when is_binary(msg) ->
        msg

      _ ->
        read_input(args, opts)
    end
  end

  defp read_input([]), do: IO.read(:stdio, :eof)

  defp read_input(args, opts) do
    case {opts[:file], args} do
      {nil, []} -> IO.read(:stdio, :eof)
      {nil, [source]} when source in ["-", "--"] -> IO.read(:stdio, :eof)
      {nil, values} -> Enum.join(values, " ")
      {source, []} when source in ["-", "--"] -> IO.read(:stdio, :eof)
      {path, []} -> File.read!(path)
      {_path, _values} -> fail("Use either --file or positional input, not both")
    end
  end

  defp write_output(output, true), do: IO.puts(Base.encode16(output, case: :lower))
  defp write_output(output, false), do: IO.write(output)

  defp format_invalid_options(options) do
    options
    |> Enum.map_join(", ", fn
      {option, nil} -> option
      {option, value} -> "#{option}=#{value}"
    end)
  end

  defp sm4_input_hex?(opts, hex?, decrypt?) do
    Keyword.get(opts, :input_hex, false) or (hex? and decrypt?)
  end

  defp sm4_output_hex?(opts, hex?, decrypt?) do
    Keyword.get(opts, :output_hex, false) or (hex? and not decrypt?)
  end

  defp ensure_sm3_supported! do
    unless Guomi.SM3.supported?() do
      fail("SM3 is not supported on this system")
    end
  end

  defp parse_hex_or_exit(nil, _), do: nil

  defp parse_hex_or_exit(hex_string, name) do
    case hex_string |> String.trim() |> Base.decode16(case: :mixed) do
      {:ok, binary} ->
        binary

      :error ->
        fail("Invalid hex encoding for #{name}")
    end
  end

  defp required_hex_or_exit(nil, name) do
    fail("Missing required option --#{name}")
  end

  defp required_hex_or_exit(hex_string, name), do: parse_hex_or_exit(hex_string, name)

  defp validate_sm4_iv("cbc", nil) do
    fail("Missing required option --iv")
  end

  defp validate_sm4_iv("cbc", iv), do: parse_hex_or_exit(iv, "iv")
  defp validate_sm4_iv(_mode, _iv), do: nil

  defp validate_sm4_parameter("cbc", opts), do: validate_sm4_iv("cbc", opts[:iv])

  defp validate_sm4_parameter("ctr", opts) do
    opts[:counter]
    |> required_hex_or_exit("counter")
    |> validate_sm4_counter()
  end

  defp validate_sm4_parameter(_mode, _opts), do: nil

  defp validate_sm4_counter(counter) when byte_size(counter) == 16, do: counter
  defp validate_sm4_counter(_counter), do: fail("Invalid counter size (must be 16 bytes)")

  defp parse_sm4_padding("ctr", opts) do
    if opts[:padding], do: fail("SM4 CTR does not use padding"), else: :none
  end

  defp parse_sm4_padding(_mode, opts) do
    parse_padding_or_exit(Keyword.get(opts, :padding, "pkcs7"))
  end

  defp parse_padding_or_exit("pkcs7"), do: :pkcs7
  defp parse_padding_or_exit("none"), do: :none

  defp parse_padding_or_exit(padding) do
    fail("Invalid padding option: #{padding} (use 'pkcs7' or 'none')")
  end

  defp fail(messages) when is_list(messages) do
    Enum.each(messages, &IO.puts(:stderr, "Error: #{&1}"))
    System.halt(1)
  end

  defp fail(message), do: fail([message])

  defp format_sm4_error(:invalid_key_size), do: "Invalid key size (must be 16 bytes)"
  defp format_sm4_error(:invalid_iv_size), do: "Invalid IV size (must be 16 bytes)"
  defp format_sm4_error(:invalid_block_size), do: "Invalid block size"
  defp format_sm4_error(:invalid_padding), do: "Invalid padding option"
  defp format_sm4_error(:unsupported), do: "SM4 is not supported on this system"

  defp format_sm4_error({:invalid_mode, mode}),
    do: "Invalid mode: #{mode} (use 'ecb', 'cbc', or 'ctr')"

  defp format_sm4_error(_), do: "Unknown error"

  defp format_sm2_error(:decryption_failed), do: "Decryption failed"
  defp format_sm2_error(:invalid_input), do: "Invalid message input"
  defp format_sm2_error(:invalid_ciphertext), do: "Invalid ciphertext"
  defp format_sm2_error(:invalid_key), do: "Invalid key"
  defp format_sm2_error(:invalid_signature), do: "Invalid signature"
  defp format_sm2_error(:unsupported), do: "SM2 is not supported on this system"
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
        guomi sm3 --hex --file file.txt

        # SM4 encryption
        echo "secret" | guomi sm4 --key 0123456789abcdef0123456789abcdef
        guomi sm4 --decrypt --hex --key 0123456789abcdef0123456789abcdef < ciphertext.bin

        # SM2 key generation
        guomi sm2 --generate

        # SM2 sign
        echo "message" | guomi sm2 --sign --private-key <hex-key>

        # SM2 verify
        guomi sm2 --verify --public-key <hex-key> --signature <hex-sig> --file message.txt
    """)
  end

  defp print_sm3_help do
    IO.puts("""
    guomi sm3 - Compute SM3 hash

    USAGE:
        guomi sm3 [options] [input]

    OPTIONS:
        --hex         Output hash as hexadecimal (default: binary)
        --file <path> Read input from a file (use - for stdin)
        --help        Show this help message

    INPUT:
        If no input is specified, reads from stdin.
        Positional arguments are joined with spaces and treated as the message.
        Use --file <path> to read from a file, or - to read from stdin.

    EXAMPLES:
        echo -n "hello" | guomi sm3
        guomi sm3 --hex hello world
        guomi sm3 --hex --file file.txt
    """)
  end

  defp print_sm4_help do
    IO.puts("""
    guomi sm4 - SM4 encryption/decryption

    USAGE:
        guomi sm4 [options] [input]

    OPTIONS:
        --mode <mode>     Encryption mode: ecb (default), cbc, or ctr
        --key <hex>       Encryption key (16 bytes hex, required)
        --iv <hex>        Initialization vector (16 bytes hex, required for CBC)
        --counter <hex>   Initial counter (16 bytes hex, required for CTR)
        --decrypt         Decrypt instead of encrypt
        --hex             Compatibility shortcut: output hex when encrypting, input hex when decrypting
        --input-hex       Treat input as hexadecimal text
        --output-hex      Print output as hexadecimal text
        --padding <pad>   Padding: pkcs7 (default) or none
        --file <path>     Read input from a file (use - for stdin)
        --help            Show this help message

    INPUT:
        If no input is specified, reads from stdin.
        Positional arguments are joined with spaces and treated as the input.
        Use --file <path> to read from a file, or - to read from stdin.

    EXAMPLES:
        # Encrypt with ECB
        echo "secret" | guomi sm4 --key 0123456789abcdef0123456789abcdef

        # Encrypt with CBC
        echo "secret" | guomi sm4 --mode cbc --key 0123456789abcdef0123456789abcdef --iv 00000000000000000000000000000000

        # Decrypt hex ciphertext
        guomi sm4 --decrypt --hex --key 0123456789abcdef0123456789abcdef < ciphertext.hex

        # Decrypt CBC mode
        guomi sm4 --decrypt --mode cbc --key 0123456789abcdef0123456789abcdef --iv 00000000000000000000000000000000 < ciphertext.bin

        # Encrypt with CTR (the key/counter pair must never be reused)
        guomi sm4 --mode ctr --key 0123456789abcdef0123456789abcdef --counter 00000000000000000000000000000001 secret
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
        --file <path>       Read message/ciphertext from a file (use - for stdin)
        --signature <hex>   Signature to verify (hex encoded)
        --ciphertext <hex>  Ciphertext to decrypt (hex encoded)
        --help            Show this help message

    INPUT:
        If no input is specified, reads from stdin.
        Positional arguments are joined with spaces and treated as the message.
        Use --file <path> to read from a file, or - to read from stdin.
        --message takes precedence for sign, verify, and encrypt operations.

    EXAMPLES:
        # Generate keypair
        guomi sm2 --generate

        # Sign a message
        echo "message" | guomi sm2 --sign --private-key <hex-key>

        # Verify a signature
        guomi sm2 --verify --public-key <hex-key> --signature <hex-sig> --file message.txt

        # Encrypt a message
        echo "secret" | guomi sm2 --encrypt --public-key <hex-key>

        # Decrypt a ciphertext
        guomi sm2 --decrypt --private-key <hex-key> --ciphertext <hex-cipher>
    """)
  end
end
