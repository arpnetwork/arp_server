defmodule ARP.API.JSONRPC2.Protocol do
  @moduledoc false

  alias ARP.{Crypto, Nonce, Utils}
  alias JSONRPC2.Misc

  def verify(method, params, nonce, sign, self_addr) do
    decoded_nonce = Utils.decode_hex(nonce)
    msg = encode_sign_msg(method, params, nonce, self_addr)

    with <<_::binary-size(130)>> <- sign,
         {:ok, address} <- Crypto.eth_recover(msg, sign),
         :ok <- Nonce.check_and_update_nonce(address, self_addr, decoded_nonce) do
      {:ok, address}
    else
      {:error, reason} when is_atom(reason) ->
        {:error, reason}

      {:error, reason} when is_binary(reason) ->
        msg = str_to_atom(reason)
        {:error, msg}

      _ ->
        {:error, :invalid_sign}
    end
  end

  def verify(method, params, sign, self_addr) do
    msg = encode_sign_msg(method, params, self_addr)

    with <<_::binary-size(130)>> <- sign,
         {:ok, address} <- Crypto.eth_recover(msg, sign) do
      {:ok, address}
    else
      {:error, reason} when is_atom(reason) ->
        {:error, reason}

      {:error, reason} when is_binary(reason) ->
        msg = str_to_atom(reason)
        {:error, msg}

      _ ->
        {:error, :invalid_sign}
    end
  end

  def sign(method, params, nonce, to_addr, private_key) do
    msg = encode_sign_msg(method, params, nonce, to_addr)
    Crypto.eth_sign(msg, private_key)
  end

  def verify_resp_sign(result, self_addr, device_addr) do
    sign = result["sign"]
    data = Map.delete(result, "sign")
    data_sign = encode_sign_msg(data, self_addr)
    {:ok, address} = Crypto.eth_recover(data_sign, sign)

    if address == device_addr do
      true
    else
      false
    end
  end

  def response({:error, msg}) do
    new_msg =
      unless is_atom(msg) do
        str_to_atom(msg)
      end

    {:error, new_msg || msg}
  end

  def response(:error) do
    {:error, :invalid_params}
  end

  def response(nil) do
    {:error, :invalid_params}
  end

  def response(data) do
    {:ok, data}
  end

  def response(data, nonce, to_addr, private_key) when is_map(data) do
    data = Map.put(data, :nonce, nonce)
    data_sign = data |> encode_sign_msg(to_addr) |> Crypto.eth_sign(private_key)
    {:ok, Map.put(data, :sign, data_sign)}
  end

  def response(data, to_addr, private_key) when is_map(data) do
    data_sign = data |> encode_sign_msg(to_addr) |> Crypto.eth_sign(private_key)
    {:ok, Map.put(data, :sign, data_sign)}
  end

  def get_method(module, env) do
    mod = module |> Module.split() |> List.last() |> String.downcase() |> String.to_atom()
    fun_name = elem(env.function, 0)
    Misc.to_method_name(mod, fun_name)
  end

  # Encode params for JSONRPC2 request sign.
  defp encode_sign_msg(method, params, nonce, to_addr)
       when is_binary(method) and is_list(params) and is_binary(to_addr) do
    "#{method}:#{Enum.join(params, ":")}:#{nonce}:#{to_addr}"
  end

  defp encode_sign_msg(method, params, to_addr)
       when is_binary(method) and is_list(params) and is_binary(to_addr) do
    "#{method}:#{Enum.join(params, ":")}:#{to_addr}"
  end

  # Encode params for JSONRPC2 response sign.
  defp encode_sign_msg(params, to_addr) when is_map(params) and is_binary(to_addr) do
    encoded_params =
      params
      |> Enum.sort(fn {k1, _}, {k2, _} -> k1 < k2 end)
      |> Enum.map_join(":", fn {_, v} -> v end)

    "#{encoded_params}:#{to_addr}"
  end

  defp str_to_atom(msg) do
    msg |> String.downcase() |> String.replace(" ", "_") |> String.to_atom()
  end
end
