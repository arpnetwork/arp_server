defmodule ARP.Dapp do
  @moduledoc false

  require Logger

  alias ARP.{Account, Contract, DappPromise, DevicePool, Nonce, Promise, Utils}
  alias ARP.API.JSONRPC2.Protocol
  alias JSONRPC2.Client.HTTP

  use GenServer, restart: :temporary

  @check_interval 1000 * 60 * 10

  @normal 0
  @dying 1
  @out_of_allowance 2

  defstruct [:address, :ip, :port, :allowance, state: @normal]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def set(pid, ip, port) do
    if pid && Process.alive?(pid) do
      GenServer.call(pid, {:set, ip, port})
    else
      {:error, :invalid_dapp}
    end
  end

  def get(pid) do
    if pid && Process.alive?(pid) do
      GenServer.call(pid, :get)
    else
      {:error, :invalid_dapp}
    end
  end

  def normal?(pid) do
    if pid && Process.alive?(pid) do
      @normal == GenServer.call(pid, :state)
    else
      false
    end
  end

  def save_promise(pid, promise, increment, tries \\ 0)

  def save_promise(pid, promise, increment, tries) when tries < 10 do
    if pid && Process.alive?(pid) do
      case GenServer.call(pid, {:save_promise, promise, increment}) do
        :await ->
          Process.sleep(100)
          save_promise(pid, promise, increment, tries + 1)

        res ->
          res
      end
    else
      {:error, :invalid_dapp}
    end
  end

  def save_promise(_pid, _promise, _increment, _tries) do
    {:error, :lost_promise}
  end

  def device_offline(pid, device_addr) do
    if pid && Process.alive?(pid) do
      GenServer.cast(pid, {:device_offline, device_addr})
    else
      {:error, :invalid_dapp}
    end
  end

  def cash(pid) do
    if pid && Process.alive?(pid) do
      GenServer.cast(pid, :cash)
    else
      {:error, :invalid_dapp}
    end
  end

  # Callbacks

  def init(opts) do
    address = opts[:address]
    ip = opts[:ip]
    port = opts[:port]

    server_addr = Account.address()
    last_promise = DappPromise.get(address) || %Promise{}

    with :ok <- check_bound(address, server_addr),
         {:ok, allowance} <- check_allowance(address, server_addr, last_promise) do
      if last_promise.cid != nil && last_promise.cid != allowance.id do
        Logger.info("find invalid promise with old cid, delete it. dapp address: #{address}")
        DappPromise.delete(address)
      end

      Process.send_after(self(), :check, @check_interval)

      {:ok,
       %__MODULE__{address: address, ip: ip, port: port, allowance: allowance, state: @normal}}
    else
      :dying ->
        do_cash(last_promise)
        {:ok, %__MODULE__{address: address, ip: ip, port: port, state: @dying}}

      :out_of_allowance ->
        {:ok, %__MODULE__{address: address, ip: ip, port: port, state: @out_of_allowance}}

      :error ->
        {:stop, :normal}
    end
  end

  def handle_call({:set, ip, port}, _from, dapp) do
    {:reply, :ok, struct(dapp, ip: ip, port: port)}
  end

  def handle_call(:get, _from, dapp) do
    {:reply, dapp, dapp}
  end

  def handle_call(:state, _from, dapp) do
    {:reply, dapp.state, dapp}
  end

  def handle_call({:save_promise, promise, increment}, _from, dapp) do
    case dapp.state do
      @normal ->
        last_promise = DappPromise.get(dapp.address)

        case check_promise(last_promise, promise, increment, dapp.allowance) do
          :ok ->
            DappPromise.set(dapp.address, struct(promise, paid: last_promise.paid))

            if promise.amount == dapp.allowance.amount do
              do_cash(promise)
              {:reply, :ok, struct(dapp, state: @out_of_allowance)}
            else
              {:reply, :ok, dapp}
            end

          :wait ->
            {:reply, :wait, dapp}

          :out_of_allowance ->
            {:reply, {:error, :out_of_allowance}, dapp}

          :invalid_promise ->
            {:reply, {:error, :invalid_promise}, dapp}
        end

      @dying ->
        {:reply, {:error, :expired_in_one_day}, dapp}

      @out_of_allowance ->
        {:reply, {:error, :out_of_allowance}, dapp}
    end
  end

  def handle_cast({:device_offline, device_addr}, dapp) do
    if dapp.ip && dapp.port do
      Task.start(fn ->
        method = "device_offline"
        sign_data = [device_addr]

        send_request(dapp.address, dapp.ip, dapp.port, method, sign_data)
      end)
    end

    {:noreply, dapp}
  end

  def handle_cast(:cash, dapp) do
    with promise when not is_nil(promise) <- DappPromise.get(dapp.address) do
      do_cash(promise)
    end

    {:noreply, dapp}
  end

  def handle_info(:check, dapp) do
    # check expired and allowance
    address = dapp.address
    server_addr = Account.address()
    last_promise = DappPromise.get(address) || %Promise{}

    dapp =
      with :ok <- check_bound(address, server_addr),
           {:ok, allowance} <- check_allowance(address, server_addr, last_promise) do
        struct(dapp, allowance: allowance, state: @normal)
      else
        :dying ->
          # release devices
          DevicePool.release_by_dapp(address)
          do_cash(last_promise)
          struct(dapp, state: @dying)

        :out_of_allowance ->
          do_cash(last_promise)
          struct(dapp, state: @out_of_allowance)

        _ ->
          dapp
      end

    Process.send_after(self(), :check, @check_interval)

    {:noreply, dapp}
  end

  def handle_info({_ref, {:do_cash_result, result}}, dapp) do
    Logger.info("do cash result #{dapp.address} #{result}.")

    case result do
      :success ->
        with promise when not is_nil(promise) <- DappPromise.get(dapp.address),
             %{cid: cid} = promise,
             {:ok, %{id: ^cid, paid: paid}} <-
               Contract.bank_allowance(dapp.address, Account.address()) do
          DappPromise.set(dapp.address, struct(promise, paid: paid))
        end

      :failure ->
        with promise when not is_nil(promise) <- DappPromise.get(dapp.address),
             {:ok, %{id: cid, paid: paid}} <-
               Contract.bank_allowance(dapp.address, Account.address()) do
          if promise.cid != cid do
            DappPromise.delete(dapp.address)
          else
            DappPromise.set(dapp.address, struct(promise, paid: paid))
          end
        end

      :retry ->
        do_cash(DappPromise.get(dapp.address))
    end

    {:noreply, dapp}
  end

  def handle_info(_msg, dapp) do
    {:noreply, dapp}
  end

  defp check_bound(dapp_addr, server_addr) do
    with {:ok, %{expired: bind_expired, server: server}} <-
           Contract.get_dapp_bind_info(dapp_addr, server_addr) do
      now = DateTime.utc_now() |> DateTime.to_unix()
      one_day = 60 * 60 * 24

      cond do
        server != server_addr ->
          Logger.info("dapp is not bound. dapp address: #{dapp_addr}")
          :error

        bind_expired != 0 && now >= bind_expired - one_day ->
          Logger.info("dapp is dying. dapp address: #{dapp_addr}")
          :dying

        true ->
          :ok
      end
    end
  end

  defp check_allowance(dapp_addr, server_addr, last_promise) do
    with {:ok, allowance} <- Contract.bank_allowance(dapp_addr, server_addr) do
      %{id: id, amount: amount, paid: paid, expired: expired, proxy: proxy} = allowance
      now = DateTime.utc_now() |> DateTime.to_unix()
      one_day = 60 * 60 * 24
      registry_addr = Application.get_env(:arp_server, :registry_contract_address)

      cond do
        id == 0 || proxy != registry_addr ->
          Logger.info("dapp is not approved. dapp address: #{dapp_addr}")
          :error

        paid == amount || (last_promise.cid == allowance.id && last_promise.amount == amount) ->
          Logger.info("out of allowance. dapp address: #{dapp_addr}")
          :out_of_allowance

        expired != 0 && now >= expired - one_day ->
          Logger.info("dapp is dying. dapp address: #{dapp_addr}")
          :dying

        true ->
          {:ok, allowance}
      end
    end
  end

  defp check_promise(last_promise, promise, increment, allowance) do
    cond do
      promise.amount > allowance.amount ->
        :out_of_allowance

      is_nil(last_promise) ->
        # first pay or lost data
        :ok

      last_promise.cid != promise.cid ->
        :invalid_promise

      promise.amount - last_promise.amount == increment ->
        :ok

      promise.amount - last_promise.amount > increment ->
        :wait

      true ->
        :invalid_promise
    end
  end

  defp do_cash(promise) do
    Task.async(fn ->
      server_addr = Account.address()
      private_key = Account.private_key()

      with false <- is_nil(promise),
           {:ok, %{"status" => "0x1"}} <-
             Contract.bank_cash(
               private_key,
               promise.from,
               server_addr,
               promise.amount,
               promise.sign
             ) do
        {:do_cash_result, :success}
      else
        {:ok, %{"status" => "0x0"}} ->
          {:do_cash_result, :failure}

        {:error, _} ->
          {:do_cash_result, :retry}

        _ ->
          nil
      end
    end)
  end

  defp send_request(dapp_address, ip, port, method, data) do
    private_key = Account.private_key()
    address = Account.address()

    nonce = address |> Nonce.get_and_update_nonce(dapp_address) |> Utils.encode_integer()
    url = "http://#{ip}:#{port}"

    sign = Protocol.sign(method, data, nonce, dapp_address, private_key)

    case HTTP.call(url, method, data ++ [nonce, sign]) do
      {:ok, result} ->
        if Protocol.verify_resp_sign(result, address, dapp_address) do
          {:ok, result}
        else
          {:error, :verify_error}
        end

      {:error, err} ->
        {:error, err}
    end
  end
end
