defmodule ARP.Crypto do
  @moduledoc """
  crypto module
  """

  @base_recovery_id 27

  @doc """
  Keccak-256 hash
  """
  def keccak256(data), do: :keccakf1600.hash(:sha3_256, data)

  @doc """
  string sign to {v, r, s}
  """
  def decode_sign(signature) do
    <<r::binary-size(64), s::binary-size(64), v::binary-size(2)>> = signature
    {String.to_integer(v, 16), String.to_integer(r, 16), String.to_integer(s, 16)}
  end

  def msg_hash(msg) do
    keccak256("\x19Ethereum Signed Message:\n" <> Integer.to_string(String.length(msg)) <> msg)
  end

  @doc """
  get eth address
  """
  def get_eth_addr(public_key) do
    <<_::size(8), key::binary-size(64)>> = Base.decode16!(public_key, case: :mixed)
    <<_::binary-size(12), eth_addr::binary-size(20)>> = keccak256(key)
    "0x" <> Base.encode16(eth_addr, case: :lower)
  end

  @doc """
  get public key from private key
  """
  def eth_privkey_to_pubkey(private_key) do
    {:ok, public_key} =
      Base.decode16!(private_key, case: :mixed) |> :libsecp256k1.ec_pubkey_create(:uncompressed)

    Base.encode16(public_key, case: :lower)
  end

  @doc """
  eth_sign
  """
  @spec eth_sign(String.t(), String.t()) :: String.t()
  def eth_sign(msg, private_key) do
    hash = keccak256(msg)

    {:ok, rs, v} =
      :libsecp256k1.ecdsa_sign_compact(
        hash,
        Base.decode16!(private_key, case: :mixed),
        :default,
        <<>>
      )

    Base.encode16(rs <> <<@base_recovery_id + v>>, case: :lower)
  end

  @doc """
  eth_verify
  return: :ok / :error
  """
  def eth_verify(msg, sign, public_key) do
    hash = keccak256(msg)

    :libsecp256k1.ecdsa_verify_compact(
      hash,
      Base.decode16!(sign, case: :mixed),
      Base.decode16!(public_key, case: :mixed)
    )
  end

  @doc """
  ecRecover
  return: eth address
  """
  def eth_recover(msg, sign) do
    {v, _r, _s} = decode_sign(sign)
    recovery_id = v - @base_recovery_id
    hash = keccak256(msg)

    case :libsecp256k1.ecdsa_recover_compact(
           hash,
           Base.decode16!(sign, case: :mixed),
           :uncompressed,
           recovery_id
         ) do
      {:ok, public_key} ->
        addr = public_key |> Base.encode16(case: :lower) |> get_eth_addr()
        {:ok, addr}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  get private key from keystore
  """
  def decrypt_keystore(keystore, auth) do
    try do
      decrpt_key(keystore, auth)
    rescue
      _e ->
        :error
    end
  rescue
    _ ->
      :error
  end

  defp decrpt_key(%{} = keystore, auth) do
    with {:ok, mac} <- Base.decode16(keystore[:crypto][:mac], case: :mixed),
         {:ok, iv} <- Base.decode16(keystore[:crypto][:cipherparams][:iv], case: :mixed),
         {:ok, cipher_text} <- Base.decode16(keystore[:crypto][:ciphertext], case: :mixed),
         {:ok, derived_key} <- get_kdf_key(keystore[:crypto], auth) do
      # check mac
      calc_mac = keccak256(String.slice(derived_key, 16, 16) <> cipher_text)

      if calc_mac == mac do
        case keystore[:version] do
          1 ->
            # TODO: need test
            {:ok,
             aes_cbc_decrypt(
               String.slice(derived_key, 0, 16) |> keccak256() |> String.slice(0, 16),
               cipher_text,
               iv
             )
             |> Base.encode16(case: :lower)}

          3 ->
            {:ok,
             aes_ctrxor(String.slice(derived_key, 0, 16), cipher_text, iv)
             |> Base.encode16(case: :lower)}

          _ ->
            :error
        end
      else
        :error
      end
    else
      _ ->
        :error
    end
  end

  defp get_kdf_key(%{} = crypto, auth) do
    with {:ok, salt} <- Base.decode16(crypto[:kdfparams][:salt], case: :mixed) do
      dk_len = crypto[:kdfparams][:dklen]

      if crypto[:kdf] == "scrypt" do
        n = crypto[:kdfparams][:n]
        r = crypto[:kdfparams][:r]
        p = crypto[:kdfparams][:p]

        if dk_len != nil && n != nil && r != nil && p != nil do
          {:ok, :erlscrypt.scrypt(auth, salt, n, r, p, dk_len)}
        else
          :error
        end
      else
        c = crypto[:kdfparams][:c]

        if dk_len != nil && c != nil do
          :pbkdf2.pbkdf2(:sha256, auth, salt, c, dk_len)
        else
          :error
        end
      end
    else
      _ ->
        :error
    end
  end

  defp aes_ctrxor(key, cipher_text, iv) do
    state = :crypto.stream_init(:aes_ctr, key, iv)
    {_new_state, plain_text} = :crypto.stream_decrypt(state, cipher_text)
    plain_text
  end

  defp aes_cbc_decrypt(key, cipher_text, iv) do
    :crypto.block_decrypt(:aes_cbc, key, iv, cipher_text)
  end
end
