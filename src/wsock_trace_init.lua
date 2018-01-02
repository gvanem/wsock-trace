-- wsock_trace_init.lua
--

function os_details()
  return string.format ("%s on %s (%s)", jit.version, jit.os, jit.arch);
end

function __FILE__()
  local src = debug.getinfo(2,'S').source
  return string.sub (src,2)
end

--- Try the MinGW base names first.

if jit.arch == "x64" then
  ws_name = "wsock_trace_mw_x64"
else
  ws_name = "wsock_trace_mw"
end

if not package.loaded [ws_name] then
  ws = require (ws_name)
else
  --- Then if 'ws == nil', try the MSVC base names.

  if jit.arch == "x64" then
    ws_name = "wsock_trace_x64"
  else
    ws_name = "wsock_trace"
  end
  ws = require (ws_name)
end

who_am_I = __FILE__()

ws.trace_puts (string.format("  Hello from '~1%s~0': ~2%s~0.\n", who_am_I, os_details()))
ws.trace_puts ("  ~1package.path[]: " .. package.path .. '.~0\n')

if ws then
  ws.trace_puts (string.format("  I am importing from '~1%s~0'\n", ws.get_dll_name()))
endif
