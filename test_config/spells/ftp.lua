
--[[

  This spell identifies the ftp protocol (RFC 959)

  Note - FTP uses two connections, one for control and one for data, we
  are only looking at the control connection here

  When a FTP server is ready it will send a:
  
    "220 Service ready for new user",

  If it is not ready it might send other codes like:
  
    "120 Service ready in nnn minutes"
    "421 Service not available, closing control connection"

  We are only concerned with a connections that are used, so look for
  the "220..." response.

  There are no requirements in the standard for what comes after the
  initial 3 digit number, so this spell just looks for the 220 - which
  unfortunately isn't unique and also used by e.g. SMTP (RFC 5321).

  However in FTP the client should eventually send a "USER" response, 
  for unsecure instances or an "AUTH" for secure ones (RFC 2228), where
  e.g. SMTP will respond with a EHLO/HELO

  Note, as this is a text based protocol and there are no context
  awarenes in the spell, it might lead to false positives, and might
  get a false negative if the server isn't ready for a connection
  (if it doesn't give a 220 response)

]]

ftp_whitelist =
[[
    ftp_spell
]]

snort_whitelist_append(ftp_whitelist)

ftp_spell =    { service = 'ftp',
                 proto = 'tcp',
                 to_client = { '220' },
                 to_server = { 'USER', 'AUTH' }
               }
