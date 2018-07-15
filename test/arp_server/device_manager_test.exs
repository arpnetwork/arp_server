defmodule ARP.DeviceManagerTest do
  use ExUnit.Case

  alias ARP.DeviceManager
  alias ARP.Device

  @device_1 %Device{id: "a", cpu: "msm8974", ram: 1_945_096_192}
  @filter_1 %{"cpu" => "msm8974", "ram" => 1_945_096_192}
  @filter_2 %{"cpu" => "sdm845", "ram" => 1_945_096_192}

  setup do
    DeviceManager.start_link([])
    DeviceManager.clear()
    :ok
  end

  test "online" do
    assert {:ok, dev} = DeviceManager.online(@device_1)
    assert dev.state == 0
    assert {:error, _} = DeviceManager.online(@device_1)
  end

  test "offline" do
    DeviceManager.online(@device_1)
    assert DeviceManager.offline("a") == :ok
    assert {:error, _} = DeviceManager.offline("a")
  end

  test "request" do
    assert {:ok, dev1} = DeviceManager.online(@device_1)
    assert {:error, _} = DeviceManager.request(@filter_2, "user1")
    assert {:ok, dev2} = DeviceManager.request(@filter_1, "user2")
    assert dev1.id == dev2.id
    assert dev2.state == 1
    assert {:error, _} = DeviceManager.request(@filter_1, "user3")
  end

  test "use" do
    DeviceManager.start_link([])
    DeviceManager.online(@device_1)
    DeviceManager.request(@filter_1, "user1")
    assert {:ok, dev} = DeviceManager.use("a")
    assert dev.state == 2
  end

  test "free" do
    DeviceManager.online(@device_1)
    DeviceManager.request(@filter_1, "abc")
    DeviceManager.use("a")
    assert {:ok, dev} = DeviceManager.idle("a")
    assert dev.state == 0
  end
end
