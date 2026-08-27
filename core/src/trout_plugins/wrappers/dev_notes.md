# Wrappers

The files in this folder are wrappers for the snort libraries, made to
make it more simple to create snort plugins

## Pegs

In the default snort implementation you need to keep two different
structures in perfect sync, the peg templates you define the structure
once, and the two structures are generated.

The lookups for referencing pegs are compiletime resolved, so it doesn't
carry any penalties

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
