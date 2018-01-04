-- wsock_trace_exit.lua
--

if ws == nil then
  dofile ("wsock_trace_init.lua")
end

ws.trace_puts (string.format("  Bye from ~1%s~0 at line %d\n", __FILE__(), __LINE__()))


