defmodule ARP.DappPromise do
  use GenServer

  @file_path Application.get_env(:arp_server, :data_dir)
             |> Path.join("dapp_promise")
             |> String.to_charlist()
  @save_promise_interval 1000

  def set(dapp_addr, promise) do
    :ets.insert(__MODULE__, {dapp_addr, promise})
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

    save_promise_timer()
    {:ok, tab}
  end

  def handle_info(:save_promise, tab) do
    :ets.tab2file(tab, @file_path, extended_info: [:md5sum])

    save_promise_timer()
    {:noreply, tab}
  end

  defp save_promise_timer do
    Process.send_after(__MODULE__, :save_promise, @save_promise_interval)
  end
end
