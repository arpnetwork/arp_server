defmodule ARP.Server do
  @moduledoc false

  def info() do
    addr = ARP.Account.address()

    %{
      name: addr || "",
      country: "",
      bandwidth: ARP.Config.get(:bandwidth),
      load: ARP.Device.size(),
      maxLoad: ARP.Config.get(:max_load)
    }
  end
end
