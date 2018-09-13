defmodule ARP.Dapp do
  @moduledoc false

  require Logger

  alias ARP.{Account, Contract, DappPromise, DevicePool}

  use GenServer, restart: :temporary

  @init 0
  @normal 1
  @dying 2

  defstruct [:address, state: @init]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def first_check(dapp_addr) do
    server_addr = Account.address()

    %{id: id, expired: expired, proxy: proxy} = Contract.bank_allowance(dapp_addr, server_addr)
    %{expired: bind_expired, server: server} = Contract.get_dapp_bind_info(dapp_addr, server_addr)
    registry_addr = Application.get_env(:arp_server, :registry_contract_address)

    last_promise = DappPromise.get(dapp_addr)

    now = DateTime.utc_now() |> DateTime.to_unix()
    one_day = 60 * 60 * 24

    cond do
      id == 0 || server != server_addr || proxy != registry_addr ->
        Logger.info("dapp not approve or bind. dapp address: #{dapp_addr}")
        DappPromise.delete(dapp_addr)
        :error

      id != 0 && last_promise && last_promise.cid != id ->
        Logger.info("find invalid promise with old cid, delete it. dapp address: #{dapp_addr}")

        DappPromise.delete(dapp_addr)
        :normal

      (expired != 0 && now >= expired - one_day) ||
          (bind_expired != 0 && now >= bind_expired - one_day) ->
        Logger.info("dapp is dying. dapp address: #{dapp_addr}")
        :dying

      true ->
        :normal
    end
  end

  def normal?(pid) do
    if pid && Process.alive?(pid) do
      @normal == GenServer.call(pid, :state)
    else
      false
    end
  end

  def save_promise(pid, promise, increment) do
    if pid && Process.alive?(pid) do
      GenServer.call(pid, {:save_promise, promise, increment})
    else
      {:error, :invalid_dapp}
    end
  end

  # Callbacks

  def init(opts) do
    address = opts[:address]
    init_state = opts[:init_state]

    case init_state do
      :normal ->
        {:ok, %__MODULE__{address: address, state: @normal}}

      :dying ->
        last_promise = DappPromise.get(address)
        do_expire(address, last_promise)
        {:ok, %__MODULE__{address: address, state: @dying}}

      :error ->
        {:stop, :normal}

      nil ->
        Process.send(self(), :init, [])
        {:ok, %__MODULE__{address: address, state: @init}}
    end
  end

  def handle_call(:state, _from, dapp) do
    {:reply, dapp.state, dapp}
  end

  def handle_call({:save_promise, promise, increment}, _from, dapp) do
    if dapp.state == @normal do
      case DappPromise.get(dapp.address) do
        nil ->
          # first pay or lost data
          DappPromise.set(dapp.address, promise)
          {:reply, {:ok, increment}, dapp}

        last_promise ->
          if last_promise.cid == promise.cid && promise.amount > last_promise.amount do
            DappPromise.set(dapp.address, promise)
            {:reply, {:ok, promise.amount - last_promise.amount}, dapp}
          else
            {:reply, {:error, :invalid_promise}, dapp}
          end
      end
    else
      {:reply, {:error, :invalid_state}, dapp}
    end
  end

  def handle_info(:init, dapp) do
    case first_check(dapp.address) do
      :normal ->
        dapp = struct(dapp, state: @normal)
        {:noreply, dapp}

      :dying ->
        last_promise = DappPromise.get(dapp.address)
        do_expire(dapp.address, last_promise)
        dapp = struct(dapp, state: @dying)
        {:noreply, dapp}

      :error ->
        {:stop, :normal, dapp}
    end
  end

  def handle_info(:check, dapp) do
    if dapp.state == @normal do
      # check expired
      Task.async(fn ->
        server_addr = Account.address()

        %{amount: amount, expired: expired} = Contract.bank_allowance(dapp.address, server_addr)
        %{expired: bind_expired} = Contract.get_dapp_bind_info(dapp.address, server_addr)
        last_promise = DappPromise.get(dapp.address)

        now = DateTime.utc_now() |> DateTime.to_unix()
        one_day = 60 * 60 * 24

        if (expired != 0 && now >= expired - one_day) ||
             (bind_expired != 0 && now >= bind_expired - one_day) ||
             last_promise.amount >= amount * 0.8 do
          Logger.info("dapp is dying or approval is not enough")
          {:check_expired_result, :dying}
        else
          {:check_expired_result, :ok}
        end
      end)
    end

    {:noreply, dapp}
  end

  def handle_info({_ref, {:check_expired_result, result}}, dapp) do
    dapp =
      case result do
        :ok ->
          dapp

        :dying ->
          last_promise = DappPromise.get(dapp.address)

          do_expire(dapp.address, last_promise)
          struct(dapp, state: @dying)
      end

    {:noreply, dapp}
  end

  def handle_info({_ref, {:do_expire_result, result}}, dapp) do
    case result do
      :success ->
        Logger.info("do expire result #{dapp.address} #{result}")
        DappPromise.delete(dapp.address)
        {:stop, :normal, dapp}

      :failure ->
        Logger.info("do expire result #{dapp.address} #{result}, retry")

        last_promise = DappPromise.get(dapp.address)

        do_expire(dapp.address, last_promise)
        {:noreply, dapp}
    end
  end

  def handle_info(_msg, dapp) do
    {:noreply, dapp}
  end

  def do_expire(address, promise) do
    Task.async(fn ->
      # release devices
      DevicePool.release_by_dapp(address)

      if promise do
        server_addr = Account.address()
        private_key = Account.private_key()

        case Contract.bank_cash(private_key, address, server_addr, promise.amount, promise.sign) do
          {:ok, %{"status" => "0x1"}} ->
            {:do_expire_result, :success}

          _ ->
            {:do_expire_result, :failure}
        end
      end
    end)
  end
end
