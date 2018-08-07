defmodule ARP.System do
  @moduledoc """
  Get system load.
  """

  def load() do
    cpu = :cpu_sup.util()
    mem = :memsup.get_system_memory_data()

    mem_load =
      (1 - (mem[:free_memory] + mem[:buffered_memory] + mem[:cached_memory]) / mem[:total_memory]) *
        100

    [
      cpu: cpu,
      memory: mem_load
    ]
  end
end
