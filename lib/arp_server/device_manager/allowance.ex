defmodule ARP.DeviceManager.Allowance do
  @moduledoc """
  Allowance

  allowance = %{
    id: id,
    amount: amount,
    paid: paid,
    expired: expired,
    proxy: "0x0"
  }

  ETS table:

  "owner_addr" => %{allowance: allowance, increasing: false}
  ...

  """

  alias ARP.{Account, Config, Contract, DeviceManager}

  require Logger

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(owner_addr) do
    case :ets.lookup(__MODULE__, owner_addr) do
      [{_, info}] -> info
      [] -> nil
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def delete(owner_addr) do
    GenServer.call(__MODULE__, {:delete, owner_addr})
  end

  def set(owner_addr) do
    GenServer.call(__MODULE__, {:set, owner_addr})
  end

  def check(owner_addr, amount) do
    info = get(owner_addr)

    if info do
      allowance = info.allowance
      increasing = info.increasing

      size = DeviceManager.get_device_size(owner_addr)
      approval_amount = Config.get(:device_deposit) * size
      limit_amount = approval_amount * 0.5

      cond do
        allowance.amount < amount ->
          :error

        !increasing && allowance.amount - amount < limit_amount ->
          Logger.info(
            "device allowance less than #{limit_amount / 1.0e18} ARP, increasing. address: #{
              owner_addr
            }"
          )

          increase(owner_addr, approval_amount, allowance.expired)
          :ok

        true ->
          :ok
      end
    else
      :error
    end
  end

  def increase(owner_addr, amount, expired) do
    GenServer.cast(__MODULE__, {:increase, owner_addr, amount, expired})
  end

  # Callbacks

  def init(_opts) do
    :ets.new(__MODULE__, [:named_table, read_concurrency: true])
    {:ok, %{}}
  end

  def handle_call({:delete, owner_addr}, _from, state) do
    :ets.delete(__MODULE__, owner_addr)
    {:reply, :ok, state}
  end

  def handle_call({:set, owner_addr}, _from, state) do
    server_addr = Account.address()

    if :ets.member(__MODULE__, owner_addr) do
      {:reply, :ok, state}
    else
      with {:ok, allowance} <- Contract.bank_allowance(server_addr, owner_addr),
           true <- allowance.id > 0,
           true <- allowance.expired == 0 do
        :ets.insert(__MODULE__, {owner_addr, %{allowance: allowance, increasing: false}})
        {:reply, :ok, state}
      else
        _ ->
          {:reply, {:error, :allowance_err}, state}
      end
    end
  end

  def handle_cast({:increase, owner_addr, amount, expired}, state) do
    info = get(owner_addr)

    if info && !info.increasing do
      info = %{info | increasing: true}
      :ets.insert(__MODULE__, {owner_addr, info})

      Task.async(fn ->
        server_addr = Account.address()
        private_key = Account.private_key()

        with {:ok, %{"status" => "0x1"}} <-
               Contract.bank_increase_approval(private_key, owner_addr, amount, expired) do
          Logger.info("increase allowance success. owner_addr: #{owner_addr}")
        else
          e ->
            Logger.info(
              "increase allowance failed. owner_addr: #{owner_addr}, result = #{inspect(e)}"
            )
        end

        {:ok, new_allowance} = Contract.bank_allowance(server_addr, owner_addr)

        {:increase_result, owner_addr, new_allowance}
      end)
    end

    {:noreply, state}
  end

  def handle_info({_ref, {:increase_result, owner_addr, allowance}}, state) do
    Logger.debug(fn -> "increase result update allowance: " <> inspect(allowance) end)
    info = get(owner_addr)

    if info do
      info = %{info | allowance: allowance, increasing: false}
      :ets.insert(__MODULE__, {owner_addr, info})
    end

    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end
end
