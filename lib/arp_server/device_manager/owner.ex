defmodule ARP.DeviceManager.Owner do
  @moduledoc """
  Owner

  ETS table:

  "owner_addr" => [{"device_addr1", expired}, {"device_addr2", expired}, ...]
  "device_addr1" => "owner_addr"
  "device_addr2" => "owner_addr"
  ...

  """

  use GenServer

  alias ARP.API.TCP.DeviceProtocol
  alias ARP.{Config, Contract, Crypto}
  alias ARP.DeviceManager.Pool

  @expired_time 60 * 60 * 24 * 7
  @check_interval 1000 * 60 * 10

  @bind_type_replace 1
  @bind_type_add 2

  @doc """
  item = %{
    "sub_addr" => "",
    "salt" => "",
    "sub_sign" => ""
  }
  """
  def verify(item) do
    case Crypto.eth_recover(item["salt"], item["sub_sign"]) do
      {:ok, decode_sub_addr} -> decode_sub_addr == item["sub_addr"]
      _ -> false
    end
  end

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(owner_addr) do
    case :ets.lookup(__MODULE__, owner_addr) do
      [{_, device_addr_list}] -> device_addr_list
      [] -> []
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def get_owner_address(device_addr) do
    case :ets.lookup(__MODULE__, device_addr) do
      [{_, owner_addr}] -> owner_addr
      [] -> nil
    end
  end

  def has(owner_addr, device_addr) do
    !is_nil(owner_addr) && owner_addr == get_owner_address(device_addr)
  end

  def bind_devices(owner_addr, type, addr_sign_list) do
    if Enum.all?(addr_sign_list, fn item -> verify(item) end) do
      device_addr_list = Enum.map(addr_sign_list, fn item -> item["sub_addr"] end)

      with {:ok, approve_info} <- Contract.bank_allowance(owner_addr),
           {:ok, device_hold} <- Contract.get_device_holding() do
        msg =
          case type do
            @bind_type_replace -> :replace_devices
            @bind_type_add -> :add_devices
          end

        GenServer.call(
          __MODULE__,
          {msg, owner_addr, device_addr_list, approve_info, device_hold}
        )
      end
    else
      {:error, :invalid_sub_sign}
    end
  end

  def update_expired(owner_addr, device_addr) do
    GenServer.cast(__MODULE__, {:update_expired, owner_addr, device_addr})
  end

  # Callbacks

  def init(_opts) do
    with {:error, _} <- :ets.file2tab(file_path(), verify: true) do
      :ets.new(__MODULE__, [:named_table, read_concurrency: true])
    end

    Process.send(self(), :check, [])

    {:ok, %{}}
  end

  def handle_call(
        {:replace_devices, owner_addr, device_addr_list, approve_info, device_hold},
        _from,
        state
      ) do
    if approve_info.amount >= device_hold * length(device_addr_list) do
      current_list = get(owner_addr)

      Enum.each(current_list, fn {device_addr, _} ->
        if device_addr not in device_addr_list do
          with {_pid, dev} <- Pool.get(device_addr) do
            DeviceProtocol.repeat_connect_offline(dev.tcp_pid, device_addr)
          end

          :ets.delete(__MODULE__, device_addr)
        end
      end)

      expired = calc_expired()

      {new_list, new_helper_list} =
        Enum.reduce(device_addr_list, {[], []}, fn addr, {list, helper_list} ->
          {[{addr, expired} | list], [{addr, owner_addr} | helper_list]}
        end)

      :ets.insert(__MODULE__, {owner_addr, new_list})
      :ets.insert(__MODULE__, new_helper_list)

      write_file()
      {:reply, :ok, state}
    else
      {:reply, {:error, :device_allowance_low}, state}
    end
  end

  def handle_call(
        {:add_devices, owner_addr, device_addr_list, approve_info, device_hold},
        _from,
        state
      ) do
    expired = calc_expired()
    old_list = get(owner_addr)

    {new_list, new_helper_list} =
      Enum.reduce(device_addr_list, {old_list, []}, fn device_addr, {list, helper} = acc ->
        if List.keymember?(list, device_addr, 0) do
          acc
        else
          {[{device_addr, expired} | list], [{device_addr, owner_addr} | helper]}
        end
      end)

    if approve_info.amount >= device_hold * length(new_list) do
      :ets.insert(__MODULE__, {owner_addr, new_list})
      :ets.insert(__MODULE__, new_helper_list)

      write_file()

      {:reply, :ok, state}
    else
      {:reply, {:error, :device_allowance_low}, state}
    end
  end

  def handle_cast({:update_expired, owner_addr, device_addr}, state) do
    list = get(owner_addr)
    new_list = List.keyreplace(list, device_addr, 0, {device_addr, calc_expired()})
    :ets.insert(__MODULE__, {owner_addr, new_list})

    {:noreply, state}
  end

  def handle_info(:check, state) do
    now = DateTime.utc_now() |> DateTime.to_unix()
    list = get_all()

    for {owner_addr, device_list} <- list, is_list(device_list) do
      new_device_list =
        Enum.filter(device_list, fn {device_addr, expired} ->
          if now < expired || (now >= expired && Pool.get(device_addr) != nil) do
            true
          else
            :ets.delete(__MODULE__, device_addr)
            false
          end
        end)

      cond do
        Enum.empty?(new_device_list) ->
          :ets.delete(__MODULE__, owner_addr)

        length(device_list) != length(new_device_list) ->
          :ets.insert(__MODULE__, {owner_addr, new_device_list})

        true ->
          nil
      end
    end

    write_file()

    Process.send_after(self(), :check, @check_interval)
    {:noreply, state}
  end

  defp calc_expired do
    now = DateTime.utc_now() |> DateTime.to_unix()
    now + @expired_time
  end

  defp file_path do
    Config.get(:data_path)
    |> Path.join("device_owner")
    |> String.to_charlist()
  end

  defp write_file do
    :ets.tab2file(__MODULE__, file_path(), extended_info: [:md5sum], sync: true)
  end
end
