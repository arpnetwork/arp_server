defmodule ARP.Promise do
  @moduledoc false

  alias ARP.{Crypto, Utils}

  defstruct [:cid, :from, :to, :amount, :sign, :paid]

  def create(private_key, cid, from, to, amount, paid \\ 0) do
    decoded_from = from |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    decoded_to = to |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    data =
      <<cid::size(256), decoded_from::binary-size(20), decoded_to::binary-size(20),
        amount::size(256)>>

    sign = Crypto.eth_sign(data, private_key)

    %__MODULE__{
      cid: cid,
      from: from,
      to: to,
      amount: amount,
      sign: sign,
      paid: paid
    }
  end

  def verify(%__MODULE__{} = p, from, to) do
    cond do
      is_nil(p.cid) || is_nil(p.from) || is_nil(p.to) || is_nil(p.amount) || is_nil(p.sign) ->
        false

      p.from != from || p.to != to ->
        false

      true ->
        cid = p.cid |> Utils.decode_hex()
        from_binary = p.from |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
        to_binary = p.to |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
        amount = p.amount |> Utils.decode_hex()
        sign = p.sign

        encode = <<cid::size(256), from_binary::binary, to_binary::binary, amount::size(256)>>

        with {:ok, recover_addr} <- Crypto.eth_recover(encode, sign) do
          recover_addr == from
        else
          _ ->
            false
        end
    end
  rescue
    _ ->
      false
  end

  def encode(%__MODULE__{} = promise) do
    %__MODULE__{
      cid: promise.cid |> Utils.encode_integer(),
      from: promise.from,
      to: promise.to,
      amount: promise.amount |> Utils.encode_integer(),
      sign: promise.sign,
      paid: (promise.paid || 0) |> Utils.encode_integer()
    }
  end

  def decode(%__MODULE__{} = promise) do
    %__MODULE__{
      cid: promise.cid |> Utils.decode_hex(),
      from: promise.from,
      to: promise.to,
      amount: promise.amount |> Utils.decode_hex(),
      sign: promise.sign,
      paid: (promise.paid || "0x0") |> Utils.decode_hex()
    }
  end
end
