# Sample lua ips options script

The dhcpfind.lua script in this folder is made to illustrate how a lua script can be created so it can be used in Snort rules.

The files plugffi.lua and snort_plugin.lua are part of the snort source code distribution and only included here for convinience, they are copied unmodified from snort3/build/src/managers/

## Background

When running Snort you typically does it with a configuration file, in order to create rules a module called ips is used, this module takes a rule file as input:

*cfg.lua:*

    ips = {
 	  include = 'lua.rules'
    }

 

In the rule files ('lua.rules' in this example) we can then use filter comands like:

*lua.rules:*

    alert ip any 67 -> any 68 (
      msg:"DHCP option 50 or 1 in use";
      dhcpfind:"fail={50, 1}";
    )

This will create an alert in snort if there is communication between port 67 and 68 and the dhcpfind option (which is defined in the 'dhcpfind.lua' file)

The alert body has two part the message ('msg') that should be printed to identify the alert and the option ('dhcpfind') that will either evaluate to true or false, and hence trigger the alert or not.

It is not possible to mix ips options with build-in detection, i.e. the following will generate an error when loaded into snort:

**Invalid sample:**

    alert ip any 67 -> any 68 (
      msg:"DHCP option 50 or 1 in use";
      dhcpfind:"fail={50, 1}";
      gid:8000;
      sid:1001;
    )

Will generate an error like **ERROR: lua.rules:6 8000:1001 builtin rules do not support detection options**

## Lua Code

The script that makes an IPS Option has 3 parts, an init() function, an eval() function and a datastructure that defines the plugin.

### plugin data structure:

    plugin =
    {
        type = "ips_option",  -- only available type currently
        name = "dhcpfind",    -- rule option keyword
        version = 0           -- optional, defaults to zero
    }

The only part that should be changed are the name and version ("dhcpfind" and 0 in the above example)  the name is what you will later need to write in the ips rules. 

### init() function

    function init ()
        if args.pass ~= nil and args.fail ~= nil then
          return "Error msg about parameters"
        elseif 
          ...
        end

	 	....

        return true
    end

In the example the Init function is used to pass arguments.  The arguments are given in the rules as a string, eg.:

    alert ip any 67 -> any 68 (
      msg:"DHCP option 50 or 1 in use";
      dhcpfind:"fail={50, 1};pass={2}";
    )

#### Return value

There are two possible return values for the init function, either 'true', which means all is fine, or a string that will prevent the script being passed and be printed to the user in a snort error message (which will in turn lead to the termination of snort)

#### Argument parsing

The string argument string is a list of key value pairs, with the key and value seperated by '=' and the individual key value pairs by ';'.

The keys are variables under 'args' with the same name as the key, and the value of the variable is whatever is after the '=' sign, so if you write something like:

    dhcpfind:"fail=29" 
 
The 'args.fail' will have the value '29', and if you write something like:
 
     dhcpfind:"fail={50, 1}"

then the value of 'args.fail' will be a lua table with two entries, one holding '50' and the other '1'

There is no need/way to declare which arguments, or the type of these arguments, that can be passed to the lua script.

### eval() function

The eval function is called for each packet that should be evaluated, the snort code should then inspect the content of the package, possible analyze it like speficed on the argument line and return the result.

#### Return value

The 'eval()' function must either return 'true' or 'false'.  

A return value of 'true' means the alert in the IPS rule will trigger, a return value of 'false' means it will not trigger.

#### Analyzing packet

To get access to the packet data the 'ffi.C.get_buffer()' function can be called:

    function eval ()
        local buf = ffi.C.get_buffer()

        if buf.len < 240 then
          return false
        end

        ....
        
        return true
    end

Note: The content of the buffer is the data part of the UDP packet.

## Running the script in snort

For the code to run two steps can be made (it is unclear if both are really needed what each stands for and why both might be needed)

First the 'LUA_PATH' environment variable needs to be defined like:

    $ export LUA_PATH=/path/to/the/lua/script

and then snort needs to be started with the '--script-path' parameter set to the same value as 'LUA_PATH' was set to with some extras like:

    --script-path /path/to/the/lua/script/?.lua;;

## Final note on dependencies

If the lua script has dependencies to other lua scripts, then snort needs to know where to find these scripts, that is why 'plugffi.lua' and 'snort_plugin.lua' are both copied to the sam folder as 'dhcpfind.lua'.

