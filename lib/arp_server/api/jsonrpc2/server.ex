defmodule ARP.API.JSONRPC2.Server do
  @moduledoc false

  def info do
    {:ok, info} = ARP.Account.get_info()

    %{
      name: info.addr || "",
      country: "",
      bandwidth: 0,
      load: ARP.System.load()[:cpu]
    }
  end
end
