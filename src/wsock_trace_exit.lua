-- wsock_trace_exit.lua
--

-- if called by lua / luajit directly
--
-- if (... ~= 'wsock_trace_exit') then
--   dofile ("wsock_trace_init.lua")
-- end

if ws.get_trace_level() >= 1 then
  ws.trace_puts (string.format("  Bye from ~1%s~0 at line %d\n", __FILE__(), __LINE__()))
end

if package.loaded ["jit.profile"] then
  ws.trace_puts ("Stopping profiler\n")
  profile.stop()
end

