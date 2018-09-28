defmodule ARP.DevicePromise do
  alias ARP.API.JSONRPC2.Protocol
  alias JSONRPC2.Client.HTTP
  alias ARP.{Account, Promise}

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

  def get_all() do
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

  def pay(device_address, promise) do
    set(device_address, promise)
    promise_data = promise |> Promise.encode() |> Poison.encode!()

    method = "account_pay"
    sign_data = [promise_data]

    {_pid, %{ip: ip, port: port}} = ARP.DevicePool.get(device_address)

    case send_request(device_address, ip, port + 1, method, sign_data) do
      {:ok, _result} ->
        :ok

      {:error, error} ->
        {:error, error}
    end
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

  defp send_request(device_address, ip, port, method, data) do
    private_key = Account.private_key()
    address = Account.address()

    nonce = ARP.Nonce.get_and_update_nonce(address, device_address) |> ARP.Utils.encode_integer()
    url = "http://#{ip}:#{port}"

    sign = Protocol.sign(method, data, nonce, device_address, private_key)

    case HTTP.call(url, method, data ++ [nonce, sign]) do
      {:ok, result} ->
        if Protocol.verify_resp_sign(result, address, device_address) do
          {:ok, result}
        else
          {:error, :verify_error}
        end

      {:error, err} ->
        {:error, err}
    end
  end
end
