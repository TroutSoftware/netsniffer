# Wrappers

The files in this folder are wrappers for the snort libraries, made to
make it more simple to create snort plugins

## Pegs

In the default snort implementation you need to keep two different
structures in perfect sync, the peg templates you define the structure
once, and the two structures are generated.

Instead of the native system you can now define pegs like:
---
using Pegs = PegList< Peg<  Name<"client_id_cache_max_size">,
                            Type<PegType::MAX>,
                            HelpText<"The max number of entries found in the client id cache">
                         >,
                      Peg<  Name<"flow_count">,
                            Type<PegType::SUM>,
                            HelpText<"Total number of mqtt flows">
                         >,
                      Peg<  Name<"packages">,
                            Type<PegType::SUM>,
                            HelpText<"Total number of packages presented to flow">
                         >
                    >;
---
Pegs are updated with logic that relects their type (MAX, NOW, SUM)

So for a SUM you do: Pegs::get<"some_sum_peg_name">().inc(); // Note no object to keep track of

For MAX you do: Pegs::get<"some_max_peg_name">().max(value); // peg is only updated if value is greater than the current value

For NOW you do: Pegs::get<"some_now_peg_name">().set(value); // Will overwrite the peg with the new value

This ensures you can't e.g. put a low value into a max peg, or set a sum
peg to some value, this is important bc snort will/can manipulate the
contents of the pegs depending on their type, and the snort code has
expectations to the use of them

NOTE: If two modules has the exact same pegs type definition (down to
every help text being exact the same, and the individual Pegs listed in
the same order) they will currently share pegs, this will be fixed when
the template library is updated to handle worker threads, for now it's
only working with snort threads

## Parameters

There is a lot of boiler plate code for common parameters with the
parameters templates, the parameters and settings are incoorporated,
with a single definiton like:

using namespace trout::templates;
// clang-format off
using Settings = ParamList< Param<  Name<"first_parameter">,
                                    Type<ParameterType::Bool>,
                                    DefaultValue<"true">,
                                    HelpText<"The first parameter">>,
                            Param<  Name<"second_parameter">,
                                    Type<ParameterType::Int>,
                                    SimpleRange<"1:100">,
                                    HelpText<"My second parameter">>>;
// clang-format on

The values can then be extracted with something like:

   bool b = settings->get<"first_parameter">()
