defmodule ARP.Server do
  @moduledoc false

  def info() do
    {:ok, info} = ARP.Account.get_info()

    %{
      name: info.addr || "",
      country: "",
      bandwidth: ARP.Config.get(:bandwidth),
      load: ARP.System.load()[:cpu]
    }
  end
end
