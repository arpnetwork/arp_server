defmodule ARP.DappManager.Dapp do
  @moduledoc false

  require Logger

  alias ARP.{Account, Contract, DeviceManager, Nonce, Utils}
  alias ARP.API.JSONRPC2.Protocol
  alias JSONRPC2.Client.HTTP

  use GenServer, restart: :temporary

  @check_interval 1000 * 60 * 10

  @normal 0
  @dying 1
  @out_of_allowance 2

  defstruct [:address, :ip, :port, :allowance, balance: 0, state: @normal, devices: []]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def set_info(pid, ip, port) do
    GenServer.call(pid, {:set_info, ip, port})
  end

  def get(pid) do
    GenServer.call(pid, :get)
  end

  def normal?(pid) do
    @normal == GenServer.call(pid, :state)
  end

  def save_promise(pid, promise, increment) do
    GenServer.call(pid, {:save_promise, promise, increment})
  end

  def device_offline(pid, device_addr) do
    GenServer.cast(pid, {:device_offline, device_addr})
  end

  def cash(pid) do
    GenServer.cast(pid, :cash)
  end

  # Callbacks

  def init(opts) do
    address = opts[:address]
    ip = opts[:ip]
    port = opts[:port]

    server_addr = Account.address()
    last_promise = Account.get_dapp_promise(address)

    with :ok <- check_bound(address, server_addr),
         {:ok, allowance} <- check_allowance(address, server_addr, last_promise) do
      if last_promise != nil && last_promise.cid != allowance.id do
        Logger.info("find invalid promise with old cid, delete it. dapp address: #{address}")
        Account.delete_dapp_promise(address)
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

  def handle_call({:set_info, ip, port}, _from, dapp) do
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
        last_promise = Account.get_dapp_promise(dapp.address)

        case check_promise(last_promise, promise, increment, dapp.allowance, dapp.balance) do
          :ok ->
            balance =
              if last_promise do
                Account.set_dapp_promise(dapp.address, struct(promise, paid: last_promise.paid))
                promise.amount - last_promise.amount - increment + dapp.balance
              else
                Account.set_dapp_promise(dapp.address, struct(promise, paid: 0))
                promise.amount - increment + dapp.balance
              end

            if promise.amount == dapp.allowance.amount do
              do_cash(promise)
              {:reply, :ok, struct(dapp, balance: balance, state: @out_of_allowance)}
            else
              {:reply, :ok, struct(dapp, balance: balance)}
            end

          :skip ->
            balance = dapp.balance - increment
            {:reply, :ok, struct(dapp, balance: balance)}

          :out_of_allowance ->
            {:reply, {:error, :out_of_allowance}, dapp}

          :invalid_promise ->
            Logger.warn(
              "Invalid promise " <>
                inspect({last_promise, promise, increment, dapp.allowance, dapp.balance})
            )

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
    with promise when not is_nil(promise) <- Account.get_dapp_promise(dapp.address) do
      do_cash(promise)
    end

    {:noreply, dapp}
  end

  def handle_info(:check, dapp) do
    Task.async(fn ->
      # check expired and allowance
      dapp_address = dapp.address
      server_addr = Account.address()
      last_promise = Account.get_dapp_promise(dapp_address)

      with :ok <- check_bound(dapp_address, server_addr),
           {:ok, allowance} <- check_allowance(dapp_address, server_addr, last_promise) do
        {:check_result, @normal, allowance}
      else
        :dying ->
          # release devices
          DeviceManager.release_by_dapp(dapp_address)
          do_cash(last_promise)
          {:check_result, @dying, nil}

        :out_of_allowance ->
          do_cash(last_promise)
          {:check_result, @out_of_allowance, nil}

        _ ->
          nil
      end
    end)

    Process.send_after(self(), :check, @check_interval)

    {:noreply, dapp}
  end

  def handle_info({_ref, {:do_cash_result, result}}, dapp) do
    Logger.info("do cash result #{dapp.address} #{result}.")
    server_address = Account.address()
    last_promise = Account.get_dapp_promise(dapp.address)

    case result do
      :success ->
        Task.start(fn ->
          with promise when not is_nil(promise) <- last_promise,
               %{cid: cid} = promise,
               {:ok, %{id: ^cid, paid: paid}} <-
                 Contract.bank_allowance(dapp.address, server_address) do
            Account.set_dapp_promise(dapp.address, struct(promise, paid: paid))
          end
        end)

      :failure ->
        Task.start(fn ->
          with promise when not is_nil(promise) <- last_promise,
               {:ok, %{id: cid, paid: paid}} <-
                 Contract.bank_allowance(dapp.address, server_address) do
            if promise.cid != cid do
              Account.delete_dapp_promise(dapp.address)
            else
              Account.set_dapp_promise(dapp.address, struct(promise, paid: paid))
            end
          end
        end)

      :retry ->
        do_cash(last_promise)
    end

    {:noreply, dapp}
  end

  def handle_info({_ref, {:check_result, state, allowance}}, dapp) do
    Logger.info("check_result: #{dapp.address} state: #{state}, allowance: #{inspect(allowance)}")

    dapp =
      if allowance do
        struct(dapp, state: state, allowance: allowance)
      else
        struct(dapp, state: state)
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

        paid == amount ||
            (last_promise != nil && last_promise.cid == allowance.id &&
               last_promise.amount == amount) ->
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

  defp check_promise(last_promise, promise, increment, allowance, balance) do
    cond do
      promise.amount > allowance.amount ->
        :out_of_allowance

      is_nil(last_promise) ->
        # first pay or lost data
        :ok

      last_promise.cid != promise.cid ->
        :invalid_promise

      promise.amount - last_promise.amount >= increment ->
        :ok

      promise.amount < last_promise.amount && increment <= balance ->
        :skip

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

      {:error, %{message: "Nonce too low"}} ->
        nonce = get_nonce(ip, port) + 1
        Nonce.check_and_update_nonce(address, dapp_address, nonce)
        send_request(dapp_address, ip, port, method, data)

      {:error, err} ->
        {:error, err}
    end
  end

  defp get_nonce(ip, port) do
    case HTTP.call("http://#{ip}:#{port}", "nonce_get", [Account.address()]) do
      {:ok, result} ->
        Utils.decode_hex(result["nonce"])

      {:error, _} ->
        0
    end
  end
end
