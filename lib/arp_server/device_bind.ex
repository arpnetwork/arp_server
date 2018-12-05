defmodule ARP.DeviceBind do
  @moduledoc false

  use GenServer

  alias ARP.DevicePool
  alias ARP.API.TCP.DeviceProtocol

  @device_bind_path Application.get_env(:arp_server, :data_dir)
                    |> Path.join("device_bind")
                    |> String.to_charlist()

  @expired_time 60 * 60 * 24 * 7
  @check_interval 1000 * 60 * 10

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

    with {device_addr, _sub_list} <-
           Enum.find(list, fn {_device_addr, sub_list} ->
             sub_list |> Enum.map(fn {addr, _expired} -> addr end) |> Enum.member?(sub_addr)
           end) do
      {:ok, device_addr}
    else
      _ -> {:error, :not_found}
    end
  end

  def is_bind?(device_addr, sub_addr) do
    with list when list != false <- get(device_addr) do
      list |> Enum.map(fn {addr, _expired} -> addr end) |> Enum.member?(sub_addr)
    else
      _ ->
        false
    end
  end

  def add_sub_device(device_addr, sub_addr_list) do
    unless :ets.member(__MODULE__, device_addr) do
      :ets.insert_new(__MODULE__, {device_addr, []})
    end

    expired = calc_expired()

    list = get(device_addr)
    current_sub_list = Enum.map(list, fn {sub_addr, _} -> sub_addr end)

    add_sub_list =
      sub_addr_list
      |> Enum.uniq()
      |> Enum.filter(fn sub -> !Enum.member?(current_sub_list, sub) end)

    add_list = Enum.map(add_sub_list, fn x -> {x, expired} end)
    new_list = add_list ++ list
    :ets.insert(__MODULE__, {device_addr, new_list})
    GenServer.cast(__MODULE__, :write)
    :ok
  end

  def delete_all_and_add_sub_device(device_addr, sub_addr_list) do
    current_list = get(device_addr)

    if current_list != false do
      Enum.each(current_list, fn {sub_addr, _} ->
        case DevicePool.get(sub_addr) do
          {_pid, dev} -> DeviceProtocol.repeat_connect_offline(dev.tcp_pid, sub_addr)
          _ -> nil
        end
      end)
    end

    :ets.delete(__MODULE__, device_addr)

    expired = calc_expired()

    add_list = sub_addr_list |> Enum.uniq() |> Enum.map(fn x -> {x, expired} end)

    :ets.insert(__MODULE__, {device_addr, add_list})
    GenServer.cast(__MODULE__, :write)
    :ok
  end

  def update_expired(device_addr, sub_addr) do
    with list when list != false <- get(device_addr) do
      new_expired = calc_expired()

      new_list =
        Enum.map(list, fn {addr, expired} ->
          if addr == sub_addr do
            {addr, new_expired}
          else
            {addr, expired}
          end
        end)

      :ets.insert(__MODULE__, {device_addr, new_list})
      GenServer.cast(__MODULE__, :write)
      :ok
    else
      _ ->
        {:error, :not_found}
    end
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

    Process.send_after(self(), :check_expired, 10_000)

    {:ok, %{tab: tab}}
  end

  def handle_cast(:write, %{tab: tab} = state) do
    :ets.tab2file(tab, @device_bind_path, extended_info: [:md5sum])
    {:noreply, state}
  end

  def handle_info(:check_expired, state) do
    now = DateTime.utc_now() |> DateTime.to_unix()
    list = get_all()

    new_list =
      Enum.map(list, fn {device_addr, sub_list} ->
        new_sub_list =
          Enum.filter(sub_list, fn {sub_addr, expired} ->
            now < expired || (now >= expired && DevicePool.get(sub_addr) != nil)
          end)

        {device_addr, new_sub_list}
      end)

    :ets.insert(__MODULE__, new_list)

    del_list =
      new_list
      |> Enum.filter(fn {_device_addr, sub_list} -> sub_list == [] end)
      |> Enum.map(fn {device_addr, _sub_list} -> device_addr end)

    Enum.each(del_list, fn device_addr -> :ets.delete(__MODULE__, device_addr) end)
    GenServer.cast(__MODULE__, :write)

    Process.send_after(self(), :check_expired, @check_interval)
    {:noreply, state}
  end

  defp calc_expired do
    now = DateTime.utc_now() |> DateTime.to_unix()
    now + @expired_time
  end
end
