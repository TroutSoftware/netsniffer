--[[
 syntax is e.g.

-- To raise an alert if neither option 2, 3 or 20 are seen
alert ip any 67 -> any 68 (
  msg:"DHCP alert raised";
  dhcpfind:"pass={2, 3, 20}";
)

-- To raise an alert if either option 2, 3 or 20 are seen
alert ip any 67 -> any 68 (
  msg:"DHCP alert raised";
  dhcpfind:"fail={2, 3, 20}";
)

--]]

require("snort_plugin")

function init ()
    if args.pass ~= nil and args.fail ~= nil then
      return "Having both pass and fail can give undefined behaviors e.g. \"fail={2, 3, 20}\""
    elseif args.pass == nil and args.fail == nil then
      return "You have to specify either pass or fail options e.g. \"fail={2, 3, 20}\""
    elseif type(args.pass) ~= "table" and type(args.fail) ~= "table" then
      return "Option needs to contain a table e.g. \"fail={2, 3, 20}\""
    end

    result = {}

    if args.fail ~= nil then
      expectedReturn = false           -- the eval will return true, unless we see one of the results
      for i,j in pairs(args.fail) do
        result[j] = false
      end
    end

    if args.pass ~= nil then
      expectedReturn = true          -- the eval will return false, unless we see one of the results
      for i,j in pairs(args.pass) do
        result[j] = true
      end
    end

    return true
end

function eval ()
    -- buf is a luajit cdata
    local buf = ffi.C.get_buffer()

    --local output = string.format("%x %x %x %x %x %x %x %x", buf.data[0], buf.data[1], buf.data[2], buf.data[3], buf.data[4], buf.data[5], buf.data[6], buf.data[7])
    --print("Eval called with ", buf.len, " bytes of data - starting with: ", output)

    -- TODO: Validate beginning of the DHCP to make sure it is an dhcp pakcage
    local i = 236 -- Data before options field - See RFC2131

    -- Check we have space for magic string
    if buf.len < i + 4 then
      return false
    end

    -- Check magic string
    if buf.data[i  ] ~= 0x63 or
       buf.data[i+1] ~= 0x82 or
       buf.data[i+2] ~= 0x53 or
       buf.data[i+3] ~= 0x63 then
       return false
    end

    i = i + 4   -- Step over magic string
    local remainder = buf.len - i

    while remainder > 0 do
      local code = buf.data[i]
      i = i+1
      remainder = remainder - 1
      if code == 0 then
        -- Pad option
      elseif code == 255 then
        -- End Option
        return expectedReturn
      elseif remainder > 1 then

        local length = buf.data[i] + 1 -- The length field isn't included in the length

        if length > remainder then
          return false
        end

        if result[code] ~= nil then
          return not expectedReturn
        end

        i = i + length
        remainder = remainder - length
      end

    end
    return false
end

plugin =
{
    type = "ips_option",  -- only available type currently
    name = "dhcpfind",    -- rule option keyword
    version = 0           -- optional, defaults to zero
}

