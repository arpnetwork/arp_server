defmodule ARP.DeviceManagerTest do
  use ExUnit.Case

  alias ARP.DeviceManager
  alias ARP.Device

  @device_1 %Device{id: "a", cpu: "msm8974", ram: 1_945_096_192, ip: "127.0.0.1"}
  @filter_1 %{cpu: "msm8974", ram: 1_945_096_192}
  @filter_2 %{cpu: "sdm845", ram: 1_945_096_192}

  @pending 0
  @idle 1
  @requesting 2
  @using 3

  defmodule SimpleDeviceProtocol do
    alias ARP.API.TCP.Store

    use GenServer

    def start_link(opts) do
      {:ok, pid} = GenServer.start_link(__MODULE__, [], name: __MODULE__)
      Store.put(opts.device_id, pid)
    end

    def init(_opts) do
      {:ok, []}
    end

    def handle_info(:speed_test, state) do
      {:noreply, state}
    end
  end

  setup do
    DeviceManager.clear()

    :ok
  end

  test "online" do
    assert {:ok, dev} = DeviceManager.online(@device_1)
    assert dev.state == @pending
    assert {:error, _} = DeviceManager.online(@device_1)
  end

  test "offline" do
    DeviceManager.online(@device_1)
    assert DeviceManager.offline("a") == :ok
    assert {:error, _} = DeviceManager.offline("a")
  end

  test "request" do
    assert {:ok, dev1} = DeviceManager.online(@device_1)
    SimpleDeviceProtocol.start_link(%{device_id: dev1.id})
    DeviceManager.update_net_speed(["a"], 100, 100)
    assert {:error, _} = DeviceManager.request(@filter_2, "user1")
    assert {:ok, dev2} = DeviceManager.request(@filter_1, "user2")
    assert dev1.id == dev2.id
    assert dev2.state == @requesting
    assert {:error, _} = DeviceManager.request(@filter_1, "user3")
  end

  test "use" do
    DeviceManager.start_link([])
    {:ok, dev1} = DeviceManager.online(@device_1)
    SimpleDeviceProtocol.start_link(%{device_id: dev1.id})
    DeviceManager.update_net_speed(["a"], 100, 100)
    DeviceManager.request(@filter_1, "user1")
    assert {:ok, dev} = DeviceManager.use("a")
    assert dev.state == @using
  end

  test "idle" do
    {:ok, dev1} = DeviceManager.online(@device_1)
    SimpleDeviceProtocol.start_link(%{device_id: dev1.id})
    DeviceManager.update_net_speed(["a"], 100, 100)
    DeviceManager.request(@filter_1, "abc")
    DeviceManager.use("a")
    assert {:ok, dev} = DeviceManager.idle("a")
    assert dev.state == @idle
  end
end
