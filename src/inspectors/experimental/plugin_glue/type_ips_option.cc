#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

//#include "modbus.h"

using namespace snort;

static const char* s_name = "profinet_type";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats modbus_unit_prof;

class ModbusUnitOption : public IpsOption
{
public:
    ModbusUnitOption(uint8_t u) : IpsOption(s_name)
    { unit = u; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t unit;
};

uint32_t ModbusUnitOption::hash() const
{
    uint32_t a = unit, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool ModbusUnitOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const ModbusUnitOption& rhs = (const ModbusUnitOption&)ips;
    return ( unit == rhs.unit );
}

IpsOption::EvalStatus ModbusUnitOption::eval(Cursor&, Packet* p)
{
    std::cout << "ModbusUnitOption::eval called - ";
/*    
    RuleProfile profile(modbus_unit_prof);  // cppcheck-suppress unreadVariable

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    ModbusFlowData* mfd =
        (ModbusFlowData*)p->flow->get_flow_data(ModbusFlowData::inspector_id);

    if ( mfd and unit == mfd->ssn_data.unit )
        return MATCH;
*/

    if (p->dsize > 2 && p->data[1] == unit) {
        std::cout << "returning match for unit: " << unit << std::endl;
        return MATCH;
    }

    std::cout << "returning NO-match for unit: " << unit << " size: " << p->dsize << std::endl;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_INT, "0:255", nullptr,
      "Modbus unit ID" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check Modbus unit ID"

class ModbusUnitModule : public Module
{
public:
    ModbusUnitModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &modbus_unit_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t unit = 0;
};

bool ModbusUnitModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    unit = v.get_uint8();
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ModbusUnitModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    ModbusUnitModule* mod = (ModbusUnitModule*)m;
    return new ModbusUnitOption(mod->unit);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_profinet_type = &ips_api.base;
