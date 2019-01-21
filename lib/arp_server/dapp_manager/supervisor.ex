defmodule ARP.DappManager.Supervisor do
  @moduledoc """
  Supervisor
  """

  alias ARP.DappManager.Pool

  use Supervisor

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  def init(_arg) do
    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: :dapp_pool},
      Pool
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
