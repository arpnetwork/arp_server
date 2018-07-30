defmodule ARP.System do
  @moduledoc """
  Get system usage.
  """

  def usage() do
    cpu = :cpu_sup.util()
    mem = :memsup.get_system_memory_data()

    mem_usage =
      (1 - (mem[:free_memory] + mem[:buffered_memory] + mem[:cached_memory]) / mem[:total_memory]) *
        100

    [
      cpu: cpu,
      memory: mem_usage
    ]
  end
end
