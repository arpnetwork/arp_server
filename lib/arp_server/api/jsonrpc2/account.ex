defmodule ARP.API.JSONRPC2.Account do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, Utils, Crypto, DappPromise, DevicePromise}

  @divide_rate Application.get_env(:arp_server, :divide_rate)

  def pay(promise, device_addr, nonce, sign) do
    {:ok, %{private_key: private_key, addr: addr}} = Account.get_info()

    with {:ok, dapp_addr} <- Protocol.verify(method(), [promise, device_addr], nonce, sign, addr),
         {:ok, promise} <- Poison.decode(promise),
         true <- check_promise(promise, dapp_addr) do
      # save promise
      cid = promise["cid"] |> Utils.decode_hex()
      amount = promise["amount"] |> Utils.decode_hex()
      sign = promise["sign"]

      data = DappPromise.get(dapp_addr)

      last_amount =
        if data == nil || data["cid"] != cid do
          0
        else
          data["amount"]
        end

      if amount > last_amount do
        value = %{"cid" => cid, "amount" => amount, "sign" => sign}
        :ok = DappPromise.set(dapp_addr, value)

        # calc device amount
        %{cid: device_cid} = ARP.Device.get(device_addr)
        data = DevicePromise.get(device_addr)

        last_device_amount =
          if data == nil || data["cid"] != device_cid do
            0
          else
            data["amount"]
          end

        device_amount = calc_device_amount(amount, last_amount, last_device_amount)

        # save device promise
        if device_amount > last_device_amount do
          value = %{"cid" => device_cid, "amount" => device_amount}
          :ok = DevicePromise.set(device_addr, value)
        end

        # calc device promise
        device_promise =
          calc_device_promise(device_cid, private_key, addr, device_addr, device_amount)

        # send device promise to device
        DevicePromise.account_pay(device_addr, Poison.encode!(device_promise))

        Protocol.response(%{}, nonce, dapp_addr, private_key)
      else
        Protocol.response({:error, "amount error!"})
      end
    else
      _ ->
        Protocol.response({:error, "promise error!"})
    end
  end

  defp check_promise(promise, dapp_addr) do
    cid = promise["cid"] |> Utils.decode_hex()
    from_binary = promise["from"] |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    to_binary = promise["to"] |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    amount = promise["amount"] |> Utils.decode_hex()
    sign = promise["sign"]

    encode = <<cid::size(256), from_binary::binary, to_binary::binary, amount::size(256)>>

    {:ok, recover_addr} = Crypto.eth_recover(encode, sign)

    if recover_addr == dapp_addr do
      true
    else
      false
    end
  end

  defp calc_device_amount(amount, last_amount, last) do
    rate = @divide_rate
    add = round((amount - last_amount) * (1 - rate))
    last + add
  end

  defp calc_device_promise(cid, private_key, server_addr, device_addr, amount) do
    decode_server_addr = server_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    decode_device_addr = device_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    data =
      <<cid::size(256), decode_server_addr::binary-size(20), decode_device_addr::binary-size(20),
        amount::size(256)>>

    %{
      cid: cid |> Utils.encode_integer(),
      from: server_addr,
      to: device_addr,
      amount: amount |> Utils.encode_integer(),
      sign: Crypto.eth_sign(data, private_key)
    }
  end
end
