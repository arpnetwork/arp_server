defmodule ARP.Account.Supervisor do
  @moduledoc """
  Supervisor
  """

  alias ARP.Account.{Keystore, Promise}

  use Supervisor

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  def init(_arg) do
    children = [
      Keystore,
      Promise
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
