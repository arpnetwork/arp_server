defmodule ARP.DappPromise do
  use GenServer

  @file_path Application.get_env(:arp_server, :data_dir)
             |> Path.join("dapp_promise")
             |> String.to_charlist()

  def set(dapp_addr, promise) do
    :ets.insert(__MODULE__, {dapp_addr, promise})
    GenServer.cast(__MODULE__, :write)
  end

  def get(dapp_addr) do
    case :ets.lookup(__MODULE__, dapp_addr) do
      [{^dapp_addr, value}] ->
        value

      [] ->
        nil
    end
  end

  def get_all() do
    :ets.tab2list(__MODULE__)
  end

  def delete(dapp_addr) do
    :ets.delete(__MODULE__, dapp_addr)
    GenServer.cast(__MODULE__, :write)
  end

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  # Callbacks

  def init(_opts) do
    tab =
      case :ets.file2tab(@file_path, verify: true) do
        {:ok, tab} ->
          tab

        _ ->
          :ets.new(__MODULE__, [
            :named_table,
            :public,
            write_concurrency: true,
            read_concurrency: true
          ])
      end

    {:ok, %{tab: tab, wrote_at: 0}}
  end

  def handle_cast(:write, %{tab: tab, wrote_at: wrote_at} = state) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    if now - wrote_at > 1 do
      :ets.tab2file(tab, @file_path, extended_info: [:md5sum])
      {:noreply, %{state | wrote_at: now}}
    else
      {:noreply, state}
    end
  end
end
