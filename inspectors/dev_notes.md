# Snort Inspectors, overview and howto's

Notes on what we have found about writing snort inspectors.

## Basic structure

Snort uses a plugin pattern to extend its basic functionality, these plugins are in the form of dynamically linked components (`.so` files)

A basic snort inspector plugin consists of three parts:

  - A module, the module class takes care of setup and configuration of the inspector.
  - An inspector, the inspector is the data processing entity
  - An API struct, this struct gives snort the basic info that it needs to interface with the inspector, and it is the only component that is exported from the .so file

`inspector.cc`
```
#include "framework/inspector.h"
#include "framework/module.h"
#include "protocols/packet.h"

static const Parameter my_params[] = {
    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};


class MyModule : public Module {

...

public:
  MyModule() : Module("my_module_name",
                      "My module description",
                      my_params) {}

...

};

class MyInspector : public Inspector {

...

public:
  // Main function to look at packages
  void eval(Packet *) override {...}

...

};

const InspectApi my_api = {
    {
        PT_INSPECTOR, // Type of plugin module
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "my_module_name",                           // TODO: Find if this is a plugin-name that doesn't need to be the same as the module name
        "My plugin description as a one liner",     // TODO: Find the difference between this and the module description
        []() -> Module * { return new MyModule; },  // Function to construct a module
        [](Module *m) { delete m; },                // Function to destruct a module
    },

    IT_PASSIVE,         // This defines the type of the inspector
    PROTO_BIT__ALL,     // This tells snort how to filter data send to the inspector
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    [](Module *module) -> Inspector * {       // Function to construct an inspector
      assert(module);
      return new MyInspector(dynamic_cast<MyModule *>(module));
    },
    [](Inspector *p) { delete p; },           // Function to destruct an inspector
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] = {&my_api.base, nullptr};  // This is the single export that is needed to the .so file
```

## HowTo's
### Adding pegs

Pegs are used to collect statistics/state information about an inspector (or any other kind of snort plugins).

There are different types of pegs:
 - `SUM` tracks cumulative total number of items seen (eg #events)
 - `NOW` gives snapshot of current number of items (eg current #sessions)
 - `MAX` tracks maximum value seen (eg max #sessions)

To use a peg in code these 4 changes needs to be made to the inspector code:

1) In order to add a peg you need to define the individual pegs:

`<snipet for defining pegs>`
```
const PegInfo my_pegs_definition[] = {
    {CountType::SUM, "my_first_peg_name", "help text for my_first_peg_name"},
    {CountType::SUM, "my_second_peg_name", "help text for my_second_peg_name"},

    ...

    {CountType::END, nullptr, nullptr}};  // Must be last item, so snort is able to tell how many pegs are defined
```

2) Define a data structure to save all the pegs in, the order needs to be the exact same as used when defining them:

`<snipet for peg struct>`
```
struct MyPegStruct {
  PegCount my_first_peg;
  PegCount my_second_peg;

  ...

};
```

Note: It would be inline with the pattern used otherwise if this was declared as an array.

3) Instantiate the data structure, note how it is declared `THREAD_LOCAL` so locking isn't needed when accessing it, it is assumed, but unknown if snort deals with this correctly (it seems to be the pattern used in other inspectors):

`<snipet for peg instantiation>`
```
static THREAD_LOCAL MyPegStruct my_pegs_structure = {0, 0, ...};  // Make sure the initialization matches the struct and the peg definition
```


4) In the `MyModule` class, override the following functions from `Module`

`<snipet for module code to add the pegs>`
```
class MyModule : public Module {

  ...

  const PegInfo  *get_pegs()   const override { return              my_pegs_definition; }
        PegCount *get_counts() const override { return (PegCount *)&my_pegs_structure; }

  ...
}
```


### Adding parameters

Parameters are used to configure the plugins from the configuration file, e.g.:

`my_cfg.lua`
```
my_module_name = { my_first_parameter = 0,
                   my_second_parameter = true }
```

There is a number of types for parameters:
 - `PT_TABLE`     range is Parameter*, no default
 - `PT_LIST`      range is Parameter*, no default
 - `PT_DYNAMIC`   range is RangeQuery*
 - `PT_BOOL`      if you are reading this, get more coffee
 - `PT_INT`       signed 53 bits or less determined by range
 - `PT_INTERVAL`  string that defines an interval, bounds within range
 - `PT_REAL`      double
 - `PT_PORT`      0 to 64K-1 unless specified otherwise
 - `PT_STRING`    any string less than len chars range = "(optional)" if not required (eg on cmd line)
 - `PT_SELECT`    any string appearing in range
 - `PT_MULTI`     one or more strings appearing in range
 - `PT_ENUM`      string converted to unsigned by range sequence
 - `PT_MAC`       6-byte mac address
 - `PT_IP4`       inet_addr() compatible
 - `PT_ADDR`      ip4 or ip6 CIDR
 - `PT_BIT_LIST`  string that converts to bitset
 - `PT_INT_LIST`  string that contains ints
 - `PT_ADDR_LIST` Snort 2 ip list in [ ]
 - `PT_IMPLIED`   Rule option args w/o values eg relative

Apart from the mandatory passing of the Parameters structure to the `Module` constructor there are two parts in adding parameters to your plugin, one is the parameter definition, the other the passing of parameters.


1) Defining parameters.

The parameter defintion is done by adding an entry in the Parameter array for each parameter that is needed.

(The array is passed to the Module constructor as the third parameter.)

`<snipet for defining parameters>`
```
static const Parameter my_params[] = {
  {
    "my_first_parameter",             // Parameter name/key as used in config file
    Parameter::PT_INT,                // Type of parameter here it is an integer
    "0:max32",                        // Valid range of values, note given as a string, and since lower bounds is 0 it will be unsigned
    "47",                             // Default value - note this is a string even type is integer
    "help text for first parameter"   // Help text for the first parameter
  },
  {
   "my_second_parameter",             // Parameter name/key as used in config file
    Parameter::PT_BOOL,               // Type of parameter here it is a boolean
    nullptr,                          // There are no range parameter for a boolean
    "false",                          // Default value either "true" or "false" as strings for booleans
    "help text for second parameter"  // Help text for the second parameter
  },
  {
    nullptr,
    Parameter::PT_MAX,                // The last entry in the array must by PT_MAX to indicate the end of the parameter list
    nullptr,
    nullptr,
    nullptr
  }
};

...

class MyModule {
...
  MyModule() : Module("my_module_name", "My module description", my_params) {}
...
}
```


2) Parsing parameters

Parameters are passed by overriding the set function of the `Module` base class.

Note that for set will first be called with the default value, and then with a value set in the config file

`<snipet for parsing parameters>`
```
class MyModule : public Module {
  int32_t   value_of_my_first_parameter;
  bool      value_of_my_second_parameter;

...

  bool set(const char *, Value &val, SnortConfig *) override {
    if (val.is("my_first_parameter")) {               // Check if the parameter "key" matches the first parameter
      value_of_my_first_parameter = val.get_int32();  // Read the value part of the parameter as the correct data type
    } else if (val.is("my_second_parameter")) {       // Check if the parameter "key" matches the second parameter
      value_of_my_second_parameter = val.get_bool();  // Read the value part of the parameter as the correct data type
    } else {
      return false;                                   // Indicate we didn't handle the parameter
    }

    return true;                                      // Indicate we handled the parameter
  }

...

}
```


### Raising events that can be captured from rules files and raised as alerts

It is the IPS plugin that allows us to make rules that are matched with events from inspectors.

`my_cfg.lua`
```
my_module_name = { }

ips = {
  include = 'my_rules.rules'
}
```

`my_rules.rules`
```
alert ip any any -> any any (
  msg:"This is an alert from my_module_name";
  gid:8000;
  sid:1001;
)
```

The gid is a number that should be unique for the module, a module can have multiple sid's to indicate different events as specified below.

To be able to raise an event the following 4 steps needs to be added to the source code.

1) Define the GID and the SID's that are going to be used in the module

`<snipet for defining GID and SID's>`
```
const static unsigned my_module_gid = 8000;                 // The GID should be unique, so don't use 8000, choose your own number (max is 8129)
const static unsigned my_first_sid = 1001;                  // Each SID only needs to be unique with respect to the GID
const static unsigned my_second_sid = 1002;
```

2) Define a rule map

A rulemap contains the list of sid's you have defined, and the corresponding human readable text telling what it is

`<snipet for rule map>`
```
#include "detection/detection_engine.h"

...

static const RuleMap my_rules[] = {
  {
    my_first_sid,               // SID of first event
    "first description"         // Text for first event
  },
  {
    my_second_sid,              // SID of second event
    "second description"        // Text for second event
  },
  {0, nullptr}};                // Last element must be 0,0 to signal the end of the structure
```

3) Tell snort about the gid, and rulemap

`<snipet for parsing parameters>`
```
class MyModule : public Module {

...

  unsigned        get_gid()   const override { return my_module_gid; }  // Tells snort about the gid
  const RuleMap  *get_rules() const override { return      my_rules; }  // Tells snort about the rule map defining the SID's

...
};
```

4) Queue the event

For each packet snort is parsing there is a limited number of events that can be queued, events with lower GID's will have priority over GID's with higher numbers

`<snipet for queueing event>`
```
    DetectionEngine::queue_event(my_module_gid,   // The GID of the module
                                 my_first_sid);   // The SID identifying this specific event
```

