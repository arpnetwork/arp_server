defmodule ARP.API.JSONRPC2.Protocol do
  alias ARP.API.JSONRPC2.Nonce
  alias ARP.Crypto
  alias ARP.Utils

  def verify(method, params, nonce, sign, self_addr) do
    decoded_nonce = Utils.decode_hex(nonce)
    msg = encode_sign_msg(method, params, nonce, self_addr)

    with <<_::binary-size(130)>> <- sign,
         {:ok, address} <- Crypto.eth_recover(msg, sign),
         :ok <- Nonce.check_and_update_nonce(address, decoded_nonce) do
      {:ok, address}
    else
      {:error, reason} when is_atom(reason) ->
        msg = Atom.to_string(reason) |> String.capitalize() |> String.replace("_", " ")
        {:error, msg}

      _ ->
        {:error, "Invalid sign"}
    end
  end

  def response({:error, msg}) do
    new_msg =
      if is_atom(msg) do
        Atom.to_string(msg) |> String.capitalize() |> String.replace("_", " ")
      end

    {:invalid_params, new_msg || msg}
  end

  def response(:error) do
    :invalid_params
  end

  def response(data) do
    {:ok, data}
  end

  def response(data, nonce, to_addr, private_key) when is_map(data) do
    data = Map.put(data, :nonce, nonce)
    data_sign = data |> encode_sign_msg(to_addr) |> Crypto.eth_sign(private_key)
    {:ok, Map.put(data, :sign, data_sign)}
  end

  # Encode params for JSONRPC2 request sign.
  defp encode_sign_msg(method, params, nonce, to_addr)
       when is_binary(method) and is_list(params) and is_binary(to_addr) do
    "#{method}:#{Enum.join(params, ":")}:#{nonce}:#{to_addr}"
  end

  # Encode params for JSONRPC2 response sign.
  defp encode_sign_msg(params, to_addr) when is_map(params) and is_binary(to_addr) do
    encoded_params =
      params
      |> Enum.sort(fn {k1, _}, {k2, _} -> k1 < k2 end)
      |> Enum.map_join(":", fn {_, v} -> v end)

    "#{encoded_params}:#{to_addr}"
  end
end
