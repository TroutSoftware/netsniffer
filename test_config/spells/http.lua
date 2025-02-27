--[[
  This spell was copied/extracted from snort_defaults.lua (snort3-3.3.2.0 release) 
]]

http_whitelist =
[[
    http_methods http_spell
]]

snort_whitelist_append(http_whitelist)


http_methods =
{
    'GET', 'HEAD', 'POST', 'DELETE', 'TRACE', 'CONNECT',
    'VERSION_CONTROL', 'REPORT', 'CHECKOUT', 'CHECKIN', 'UNCHECKOUT',
    'MKWORKSPACE', 'LABEL', 'MERGE', 'BASELINE_CONTROL',
    'MKACTIVITY', 'ORDERPATCH', 'ACL', 'PATCH', 'BIND', 'LINK',
    'MKCALENDAR', 'MKREDIRECTREF', 'REBIND', 'UNBIND', 'UNLINK',
    'UPDATEREDIRECTREF', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY',
    'MOVE', 'LOCK', 'UNLOCK', 'SEARCH', 'BCOPY', 'BDELETE', 'BMOVE',
    'BPROPFIND', 'BPROPPATCH', 'POLL', 'UNSUBSCRIBE', 'X_MS_ENUMATTS',
    'NOTIFY * HTTP/', 'OPTIONS * HTTP/', 'SUBSCRIBE * HTTP/', 'UPDATE * HTTP/',
    'PUT * HTTP/', '* * HTTP/'
}


http_spell =
{
  service = 'http',
  proto = 'tcp',
  to_server = http_methods,
  to_client = { 'HTTP/' }
}
