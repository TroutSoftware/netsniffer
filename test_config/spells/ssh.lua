--[[
  This spell was copied/extracted from snort_defaults.lua (snort3-3.3.2.0 release) 
]]

ssh_whitelist =
[[
    ssh_spell
]]

snort_whitelist_append(ssh_whitelist)


ssh_spell =
{
  service = 'ssh',
  proto = 'tcp',
  to_server = { 'SSH-' },
  to_client = { 'SSH-' }
}
