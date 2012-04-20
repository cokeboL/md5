-- test suite for digest chunking.
-- This is preliminary --D.Manura, public domain.

local lib = require 'hashlib'

-- Gets random string of length n bytes.
local function random_string(n)
  local ts = {}; for i=1,n do ts[#ts+1] = string.char(math.random(255)) end
  return table.concat(ts)
end

-- Computes digest of string `s` using a randomized chunking.
-- `digest` is digest context constructor.
local nbytes = {0,1,2,63,64,65}
local function md5_random_split(s, digest)
  local ctx = digest()
  while #s > 0 or math.random() < 0.3 do
    local n = math.min(nbytes[math.random(1,#nbytes)], #s)
    local chunk = s:sub(1,n); s = s:sub(n+1)
    ctx:update(chunk)
  end
  local sum = ctx:hexadigest()
  return sum
end

-- Checks that digests of string `s` using different randomized chunks
-- are the same. `digest` is digest context constructor.
local function check_consistency(s, digest)
  local _last_sum
  for i=1,20 do
    local sum = md5_random_split(s, digest)
    assert(_last_sum or sum == sum)
    _last_sum = sum
  end
end

-- Checks that digests of randomized strings using different randomized
-- chunks are the same.  `digest` is digest context constructor.
local function check_consistency2(digest)
  for n=0,200 do
    local s = random_string(n)
    check_consistency(s, digest)
  end
end

check_consistency2(lib.md5)
check_consistency2(lib.sha1)

print 'DONE'
