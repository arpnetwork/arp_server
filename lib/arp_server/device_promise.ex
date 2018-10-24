defmodule ARP.DevicePromise do
  @moduledoc false

  use GenServer

  @file_path Application.get_env(:arp_server, :data_dir)
             |> Path.join("device_promise")
             |> String.to_charlist()

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(device_addr) do
    case :ets.lookup(__MODULE__, device_addr) do
      [{^device_addr, value}] ->
        value

      [] ->
        nil
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def set(device_addr, value) do
    :ets.insert(__MODULE__, {device_addr, value})
    GenServer.cast(__MODULE__, :write)
  end

  def delete(device_addr) do
    :ets.delete(__MODULE__, device_addr)
    GenServer.cast(__MODULE__, :write)
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

    {:ok, %{tab: tab}}
  end

  def handle_cast(:write, %{tab: tab} = state) do
    :ets.tab2file(tab, @file_path, extended_info: [:md5sum])
    {:noreply, state}
  end
end
