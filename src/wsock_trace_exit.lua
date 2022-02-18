-- wsock_trace_exit.lua
--

-- if called by lua / luajit directly
--
-- if (... ~= "wsock_trace_exit") then
--   dofile ("wsock_trace_init.lua")
-- end

if ws.get_trace_level() >= 1 then
  ws.C_puts (string.format("  Bye from ~1%s~0 at line %d\n", ws.__FILE__(), ws.__LINE__()))
end

if package.loaded ["jit.profile"] then
  ws.C_puts ("Stopping profiler\n")
  profile.stop()
end

return 3