-- wsock_trace_init.lua
--
function os_details()
  return string.format ("%s on %s (%s)",
                        jit.version, jit.os, jit.arch);
end

-- io.write ("HOME: " .. os.getenv("HOME") .. '.\n')

-- io.write ("Hello from 'wsock_trace_init.lua': " .. os_details() .. '.\n');
-- io.write ("package.path[]: " .. package.path .. '.\n');
