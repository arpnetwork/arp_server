defmodule ARP.DevicePromise do
  use GenServer

  alias ARP.API.JSONRPC2.Protocol
  alias JSONRPC2.Client.HTTP
  alias ARP.Account

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(device_addr) do
    GenServer.call(__MODULE__, {:get, device_addr})
  end

  def get_all() do
    GenServer.call(__MODULE__, :get_all)
  end

  def set(device_addr, value) do
    GenServer.call(__MODULE__, {:set, device_addr, value})
  end

  # Callbacks

  def init(_opts) do
    {:ok, init_promise()}
  end

  def handle_call({:get, device_addr}, _from, state) do
    value = Map.get(state, device_addr)
    {:reply, value, state}
  end

  def handle_call(:get_all, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:set, device_addr, value}, _from, state) do
    save_promise_to_file(device_addr, value)
    {:reply, :ok, Map.put(state, device_addr, value)}
  end

  defp save_promise_to_file(key, value) do
    file_path = System.user_home() |> Path.join("/.arp_server/device_promise")
    file_data = read_promise_file(file_path)

    encode_data = Map.put(file_data, key, value) |> Poison.encode!()
    File.write(file_path, encode_data)
  end

  defp init_promise() do
    file_path = System.user_home() |> Path.join("/.arp_server/device_promise")
    read_promise_file(file_path)
  end

  defp read_promise_file(file_path) do
    case File.read(file_path) do
      {:ok, data} ->
        if data == "" do
          %{}
        else
          Poison.decode!(data)
        end

      {:error, _} ->
        %{}
    end
  end

  def account_pay(device_address, promise) do
    method = "account_pay"
    sign_data = [promise]

    %{ip: ip, port: port} = ARP.Device.get(device_address)

    case send_request(device_address, ip, port + 1, method, sign_data) do
      {:ok, _result} ->
        :ok

      {:error, error} ->
        {:error, error}
    end
  end

  defp send_request(device_address, ip, port, method, data) do
    {:ok, %{private_key: private_key, addr: address}} = Account.get_info()

    nonce = ARP.Nonce.get_and_update_nonce(device_address) |> ARP.Utils.encode_integer()
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
