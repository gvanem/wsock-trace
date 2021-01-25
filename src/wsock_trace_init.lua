-- wsock_trace_init.lua
--

-- io = require ("io")

function os_details()
  return string.format ("%s on %s (%s)", jit.version, jit.os, jit.arch);
end

function __FILE__()
  local src = debug.getinfo (2, 'S').source
  return string.sub (src, 2)
end

function __LINE__()
  return debug.getinfo (2, 'l').currentline
end

function __FUNC__()
  return debug.getinfo (2, 'n').name
end

function local_trace (str)
  if ws.get_trace_level() >= 1 then
    ws.trace_puts (str)
  else
    io.write (str)
  end
end

WSAStartup = function (arg)
  local_trace ("Hello from WSAStartup().\n")
end

WSAStartup2 = function (arg)
  local_trace ("Hello from WSAStartup2().\n")
end

ws_name = "wsock_trace"

if package.loaded [ws_name] then
  ws.trace_puts (string.format("  Package ~2%s~0 already loaded; ~1ws -> %p~0\n", ws_name, ws))

else
  io.write ("  Loading package 'wsock_trace'...\n");
  ws = require (ws_name)
end

function trace_printf (fmt, ...)
  ws.trace_puts ("  trace_printf():\n")
  ws.trace_puts ("    fmt: " .. string.gsub(fmt, "\n", "") .. "\n")
  tab = {...}
  for key, val in pairs(tab) do
    ws.trace_puts ("    key: " .. key .. ", val: " .. val .. "\n")
  end
end

who_am_I = __FILE__()

---
-- Profiler callback.
--
function profile_callback (th, samples, vmmode)
  local_trace ("  Hello from profile_callback().\n")
end

if ws.get_profiler() then
  profile = require ("jit.profile")
  profile.start ("m", profile_callback)
end

if ws.get_trace_level() >= 1 then
  -- io.setvbuf (io.stdbuf, "line")

  ws.trace_puts (string.format("  ws.get_trace_level: ~1%d~0.\n", ws.get_trace_level()))

  if nil then
    ws.trace_puts ("  get_trace_level:    ~1" .. tostring(get_trace_level()) .. " ~0.\n")
    ws.trace_puts ("  ws.set_trace_level(0).\n")
    ws.set_trace_level (0)
  end

  if nil then
    trace_printf ("Hello from: ~1%s~0.\nVersion:  ~1%s~0. Arg-1: %d. Another arg: %s\n",
                  who_am_I, os_details(), 10, "hello")
  end

  -- ws.trace_printf ("testing ws.trace_printf():\n" ..
  --                  "  arg1 = ~1%s~0.\n" ..
  --                  "  arg2 = ~1%s~0.\n", who_am_I, os_details())

  ws.trace_puts (string.format("  Hello from:         ~1%s~0.\n", who_am_I))
  ws.trace_puts (string.format("  Version:            ~1%s~0.\n", os_details()))
  ws.trace_puts (string.format("  This is line:       ~1%d~0.\n", __LINE__()))

  ws.trace_puts ("  package.path[]:     ~1" .. package.path .. "~0.\n")
  ws.trace_puts ("  package.cpath[]:    ~1" .. package.cpath .. "~0.\n")

  ws.trace_puts (string.format("  I'm importing from: ~1%s~0.\n", ws.get_dll_full_name()))
  ws.trace_puts (string.format("  ws.get_builder():   ~1%s~0.\n", ws.get_builder()))
  ws.trace_puts (string.format("  ws.get_version():   ~1%s~0.\n", ws.get_version()))
  ws.trace_puts (string.format("  ws.get_copyright(): ~1%s~0.\n", ws.get_copyright()))
end

-- ws.register_hook (WSAStartup2, "2")

WSAStartup()
