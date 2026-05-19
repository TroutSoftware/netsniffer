

--output_to_file = { file_name = 'my_output_file.txt' }
--output_to_pipe = { pipe_name = '/tmp/llpipe_1863275496415381555' }
--output_to_pipe = { pipe_env = 'pipename' }
--output_to_stdout = {}

--log_lorth = { output = 'output_to_stdout' }
--log_bill = { output = 'output_to_pipe' }
--log_txt = { output = 'output_to_stdout' }

logger_null = {}
-- logger_stdout = { serializer = 'serializer_txt' }
serializer_txt = { }
serializer_lorth = { }

logger_stdout = { serializer = 'serializer_lorth' }

alert_lioli = { logger = 'logger_stdout' }
--alert_full = {}

alerts = { log_references = true; }

trout_netflow = { logger = 'logger_null' }

stream = {}
stream_tcp = {}
http_inspect = {}

wizard = {
    spells = { { service = 'http', proto = 'tcp', to_server = {'GET'}, to_client = {'HTTP/'} } }
}

binder = {
    { when = { service = 'http' }, use = { type = 'http_inspect' } },
    { use = { type = 'wizard' } }
}

ips = {
  include = 'test-local.rules'
}

references = {
    { name = 'bugtraq',   url = 'http://www.securityfocus.com/bid/' },
    { name = 'cve',       url = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=' },
    { name = 'arachNIDS', url = 'http://www.whitehats.com/info/IDS' },
    { name = 'osvdb',     url = 'http://osvdb.org/show/osvdb/' },
    { name = 'McAfee',    url = 'http://vil.nai.com/vil/content/v_' },
    { name = 'nessus',    url = 'http://cgi.nessus.org/plugins/dump.php3?id=' },
    { name = 'url',       url = 'http://' },
    { name = 'msb',       url = 'http://technet.microsoft.com/en-us/security/bulletin/' }
}

classifications =
{
    { name = 'not-suspicious', priority = 3,
      text = 'Not Suspicious Traffic' },

    { name = 'unknown', priority = 3,
      text = 'Unknown Traffic' },

    { name = 'bad-unknown', priority = 2,
      text = 'Potentially Bad Traffic' }
}





