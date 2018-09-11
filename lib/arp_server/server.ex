defmodule ARP.Server do
  @moduledoc false

  alias ARP.{Account, Contract, Config, Crypto, Utils}

  def info() do
    addr = Account.address()

    %{
      name: addr || "",
      country: "",
      bandwidth: Config.get(:bandwidth),
      load: ARP.Device.size(),
      maxLoad: Config.get(:max_load)
    }
  end

  def get_bind_promise(spender) do
    private_key = Account.private_key()
    owner = Account.address()

    # check server expired whether to send promise
    server_info = Contract.get_registered_info(owner)
    approve_info = Contract.bank_allowance(spender)
    device_hold = Contract.get_device_holding()

    check_time = (DateTime.utc_now() |> DateTime.to_unix()) + 60 * 60 * 24

    if (server_info.expired == 0 || server_info.expired > check_time) &&
         approve_info.amount >= device_hold do
      amount = Config.get(:device_deposit)
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

      {:ok,
       %{
         amount: amount |> Utils.encode_integer(),
         signExpired: sign_expired,
         expired: expired,
         promiseSign: "0x" <> promise_sign
       }}
    else
      :error
    end
  end
end
