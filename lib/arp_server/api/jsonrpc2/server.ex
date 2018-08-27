defmodule ARP.API.JSONRPC2.Server do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Config, Crypto, Utils}

  def info() do
    Protocol.response(ARP.Server.info())
  end

  def bind_promise(spender) do
    {:ok, %{private_key: private_key, addr: owner}} = ARP.Account.get_info()

    # check server expired whether to send voucher
    server_info = ARP.Contract.get_registered_info(owner)
    approve_info = ARP.Contract.bank_allowance(spender)
    bind_info = ARP.Contract.get_device_bind_info(spender)
    device_hold = ARP.Contract.get_device_holding()

    check_time = (DateTime.utc_now() |> DateTime.to_unix()) + 60 * 60 * 24
    empty_addr = "0x0000000000000000000000000000000000000000"

    if (server_info.expired == 0 || server_info.expired > check_time) &&
         bind_info.server == empty_addr && approve_info.amount >= device_hold do
      amount = Config.get(:amount)
      sign_expired = (DateTime.utc_now() |> DateTime.to_unix()) + 60 * 60 * 4
      expired = 0

      msg_send_binary =
        Application.get_env(:arp_server, :registry_contract_address)
        |> String.slice(2..-1)
        |> Base.decode16!(case: :mixed)

      spender_bianry = spender |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
      owner_binary = owner |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

      encode =
        <<owner_binary::binary, spender_bianry::binary, amount::size(256), expired::size(256),
          msg_send_binary::binary, sign_expired::size(256)>>

      promise_sign = Crypto.eth_sign(encode, private_key)

      Protocol.response(
        %{
          amount: amount |> Utils.encode_integer(),
          signExpired: sign_expired,
          expired: expired,
          promiseSign: "0x" <> promise_sign
        },
        spender,
        private_key
      )
    else
      Protocol.response({:error, "get voucher faild!"})
    end
  end
end
