defmodule ARP.Crypto do
  @moduledoc """
  crypto module
  """

  @doc """
  Keccak-256 hash
  """
  def keccak256(data), do: :keccakf1600.hash(:sha3_256, data)

  @doc """
  get private key from keystore
  """
  def decrypt_keystore(keystore, auth) do
    private_key = decrpt_key(keystore, auth, keystore.version)

    if private_key != :error do
      {:ok, Base.encode16(private_key, case: :lower)}
    else
      :error
    end
  end

  defp decrpt_key(%{} = keystore, auth, version) do
    mac = Base.decode16!(keystore[:crypto][:mac], case: :mixed)
    iv = Base.decode16!(keystore[:crypto][:cipherparams].iv, case: :mixed)
    cipher_text = Base.decode16!(keystore[:crypto][:ciphertext], case: :mixed)

    derived_key = get_kdf_key(keystore[:crypto], auth)

    # check mac
    calc_mac = keccak256(String.slice(derived_key, 16, 16) <> cipher_text)

    if calc_mac == mac do
      if version == 1 do
        # TODO: need test
        aes_CBC_Decrypt(
          String.slice(derived_key, 0, 16) |> keccak256() |> String.slice(0, 16),
          cipher_text,
          iv
        )
      else
        aes_CTRXOR(String.slice(derived_key, 0, 16), cipher_text, iv)
      end
    else
      :error
    end
  end

  defp get_kdf_key(crypto, auth) do
    salt = Base.decode16!(crypto.kdfparams.salt, case: :mixed)
    dk_len = crypto.kdfparams.dklen

    if crypto.kdf == "scrypt" do
      n = crypto.kdfparams.n
      r = crypto.kdfparams.r
      p = crypto.kdfparams.p

      :erlscrypt.scrypt(auth, salt, n, r, p, dk_len)
    else
      c = crypto.kdfparams.c

      {:ok, key} = :pbkdf2.pbkdf2(:sha256, auth, salt, c, dk_len)
      key
    end
  end

  defp aes_CTRXOR(key, cipher_text, iv) do
    state = :crypto.stream_init(:aes_ctr, key, iv)
    {_new_state, plain_text} = :crypto.stream_decrypt(state, cipher_text)
    plain_text
  end

  defp aes_CBC_Decrypt(key, cipher_text, iv) do
    :crypto.block_decrypt(:aes_cbc, key, iv, cipher_text)
  end
end
