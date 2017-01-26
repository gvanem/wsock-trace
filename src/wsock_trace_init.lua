-- wsock_trace_init.lua
--
function os_details()
  return string.format ("%s on %s (%s)",
                        jit.version, jit.os, jit.arch);
end

-- local ws = require "wsock_trace"

-- ws:trace_puts ("~4trace_puts()~0.\n")

-- exec ("init.lua")

io.write ("Hello from '" .. os.getenv("APPDATA") .. "\\wsock_trace_init.lua': " .. os_details() .. '.\n');
io.write ("package.path[]: " .. package.path .. '.\n');
