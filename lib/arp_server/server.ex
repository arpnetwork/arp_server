defmodule ARP.Server do
  @moduledoc false

  def info() do
    addr = ARP.Account.address()

    %{
      name: addr || "",
      country: "",
      bandwidth: ARP.Config.get(:bandwidth),
      load: ARP.System.load()[:cpu]
    }
  end
end
