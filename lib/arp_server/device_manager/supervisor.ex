defmodule ARP.DeviceManager.Supervisor do
  @moduledoc """
  Supervisor
  """

  alias ARP.DeviceManager.{Allowance, Owner, Pool, SpeedTester}

  use Supervisor

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  def init(_arg) do
    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: :device_pool},
      Pool,
      SpeedTester,
      Owner,
      Allowance
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
