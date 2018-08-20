defmodule ARP.Server do
  @moduledoc false

  def info(nonce) do
    {:ok, info} = ARP.Account.get_info()

    %{
      nonce: nonce,
      name: info.addr || "",
      country: "",
      bandwidth: Application.get_env(:arp_server, :bandwidth),
      load: ARP.System.load()[:cpu]
    }
  end
end
