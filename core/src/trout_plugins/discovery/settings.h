#ifndef settings_B8E4C71F
#define settings_B8E4C71F

// Snort includes

// System includes

// Global includes

#include "../wrappers/parameter_param.h"
#include "../wrappers/parameter_param_list.h"

// Local includes

// Debug includes

namespace trout::discovery {
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
} // namespace trout::discovery

#endif // #ifndef settings_B8E4C71F
