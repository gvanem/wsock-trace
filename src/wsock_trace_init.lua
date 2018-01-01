-- wsock_trace_init.lua
--

function os_details()
  return string.format ("%s on %s (%s)",
                        jit.version, jit.os, jit.arch);
end

function __FILE__()
  local src = debug.getinfo(2,'S').source
  return string.sub (src,2)
end

who_am_I = __FILE__()

if jit.arch == "x64" then
  ws = require ("wsock_trace_x64")
else
  ws = require ("wsock_trace")
end

ws.trace_puts (string.format("  Hello from '~1%s~0': ~2%s~0\n", who_am_I, os_details()))
ws.trace_puts ("  ~1package.path[]: " .. package.path .. '.~0\n')
