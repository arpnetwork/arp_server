defmodule ARP.DeviceBind do
  @moduledoc false

  use GenServer

  @device_bind_path Application.get_env(:arp_server, :data_dir)
                    |> Path.join("device_bind")
                    |> String.to_charlist()

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(device_addr) do
    case :ets.lookup(__MODULE__, device_addr) do
      [{_, sub_addr_list}] -> sub_addr_list
      [] -> false
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def get_device_addr(sub_addr) do
    # :ets.fun2ms(fn {device_addr, sub_list} when :erlang.is_list(sub_list) -> {device_addr, sub_list} end)
    ms = [{{:"$1", :"$2"}, [is_list: :"$2"], [{{:"$1", :"$2"}}]}]
    list = :ets.select(__MODULE__, ms)

    case Enum.find(list, fn {_device_addr, sub_list} -> Enum.member?(sub_list, sub_addr) end) do
      {device_addr, _sub_list} -> {:ok, device_addr}
      _ -> {:error, :not_found}
    end
  end

  def is_bind?(device_addr, sub_addr) do
    with list when list != false <- get(device_addr) do
      Enum.member?(list, sub_addr)
    else
      _ ->
        false
    end
  end

  def add_sub_device(device_addr, sub_addr_list) do
    unless :ets.member(__MODULE__, device_addr) do
      :ets.insert_new(__MODULE__, {device_addr, []})
    end

    list = get(device_addr)
    new_list = sub_addr_list ++ list
    :ets.insert(__MODULE__, {device_addr, new_list})
    GenServer.cast(__MODULE__, :write)
    :ok
  end

  def delete_all_and_add_sub_device(device_addr, sub_addr_list) do
    :ets.delete(__MODULE__, device_addr)
    :ets.insert(__MODULE__, {device_addr, sub_addr_list})
    GenServer.cast(__MODULE__, :write)
    :ok
  end

  # Callbacks

  def init(_opts) do
    tab =
      case :ets.file2tab(@device_bind_path, verify: true) do
        {:ok, tab} ->
          tab

        _ ->
          :ets.new(__MODULE__, [:named_table, :public, read_concurrency: true])
      end

    {:ok, %{tab: tab}}
  end

  def handle_cast(:write, %{tab: tab} = state) do
    :ets.tab2file(tab, @device_bind_path, extended_info: [:md5sum])
    {:noreply, state}
  end
end
