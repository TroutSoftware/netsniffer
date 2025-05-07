-- some HTTP and SIP methods match the whole start line to disambiguate
-- between them or, in the case of ACK, from another protocol
-- the * * patterns match unknown methods

http_methods =
{
    'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT',
    'VERSION_CONTROL', 'REPORT', 'CHECKOUT', 'CHECKIN', 'UNCHECKOUT',
    'MKWORKSPACE', 'LABEL', 'MERGE', 'BASELINE_CONTROL',
    'MKACTIVITY', 'ORDERPATCH', 'ACL', 'PATCH', 'BIND', 'LINK',
    'MKCALENDAR', 'MKREDIRECTREF', 'REBIND', 'UNBIND', 'UNLINK',
    'UPDATEREDIRECTREF', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY',
    'MOVE', 'LOCK', 'UNLOCK', 'SEARCH', 'BCOPY', 'BDELETE', 'BMOVE',
    'BPROPFIND', 'BPROPPATCH', 'POLL', 'UNSUBSCRIBE', 'X_MS_ENUMATTS',
    'NOTIFY * HTTP/', 'OPTIONS * HTTP/', 'SUBSCRIBE * HTTP/', 'UPDATE * HTTP/',
    '* * HTTP/'
}

sip_requests =
{
    'INVITE', 'CANCEL', 'BYE', 'REGISTER', 'PRACK', 'PUBLISH', 'REFER', 'INFO', 'MESSAGE',
    'NOTIFY * SIP/', 'OPTIONS * SIP/', 'SUBSCRIBE * SIP/', 'UPDATE * SIP/',
    'ACK * SIP/', '* * SIP/'
}

telnet_commands =
{
    '|FF F0|', '|FF F1|', '|FF F2|', '|FF F3|',
    '|FF F4|', '|FF F5|', '|FF F6|', '|FF F7|',
    '|FF F8|', '|FF F9|', '|FF FA|', '|FF FB|',
    '|FF FC|', '|FF FD|', '|FF FE|'
}


netflow_versions =
{
    '|00 05|', '|00 09|'
}

default_wizard =
{
    spells =
    {
        { service = 'ftp', proto = 'tcp',
          to_client = { '220*FTP', '220*FileZilla' } },

        { service = 'http', proto = 'tcp',
          to_server = http_methods, to_client = { 'HTTP/' } },

        { service = 'imap', proto = 'tcp',
          to_client = { '** OK', '** BYE', '** PREAUTH' } },

        { service = 'pop3', proto = 'tcp',
          to_client = { '+OK', '-ERR' } },

        { service = 'sip',
          to_server = sip_requests, to_client = { 'SIP/' } },

        { service = 'smtp', proto = 'tcp',
          to_server = { 'HELO', 'EHLO' },
          to_client = { '220*SMTP', '220*MAIL' } },

        { service = 'ssh', proto = 'tcp',
          to_server = { 'SSH-' }, to_client = { 'SSH-' } },

        { service = 'dce_http_server', proto = 'tcp',
          to_client = { 'ncacn_http' } },

        { service = 'dce_http_proxy', proto = 'tcp',
          to_server = { 'RPC_CONNECT' } },

    },
    hexes =
    {
        { service = 'dnp3', proto = 'tcp',
          to_server = { '|05 64|' }, to_client = { '|05 64|' } },

        { service = 'netflow', proto = 'udp',
          to_server = netflow_versions },

        { service = 'http2', proto = 'tcp',
          to_client = { '???|04 00 00 00 00 00|' },
          to_server = { '|50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 0d 0a 0d 0a 53 4d 0d 0a 0d 0a|' } },


        { service = 'ssl', proto = 'tcp',
          to_server = { '|16 03|' }, to_client = { '|16 03|' } },

        { service = 'telnet', proto = 'tcp',
          to_server = telnet_commands, to_client = telnet_commands },
    },

    curses = {'dce_udp', 'dce_tcp', 'dce_smb', 'mms', 's7commplus', 'sslv2'}
}

---------------------------------------------------------------------------
-- default references
---------------------------------------------------------------------------

default_references =
{
    { name = 'bugtraq',   url = 'http://www.securityfocus.com/bid/' },
    { name = 'cve',       url = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=' },
    { name = 'arachNIDS', url = 'http://www.whitehats.com/info/IDS' },
    { name = 'osvdb',     url = 'http://osvdb.org/show/osvdb/' },
    { name = 'McAfee',    url = 'http://vil.nai.com/vil/content/v_' },
    { name = 'nessus',    url = 'http://cgi.nessus.org/plugins/dump.php3?id=' },
    { name = 'url',       url = 'http://' },
    { name = 'msb',       url = 'http://technet.microsoft.com/en-us/security/bulletin/' }
}

---------------------------------------------------------------------------
-- default classifications
---------------------------------------------------------------------------

default_classifications =
{
    { name = 'not-suspicious', priority = 3,
      text = 'Not Suspicious Traffic' },

    { name = 'unknown', priority = 3,
      text = 'Unknown Traffic' },

    { name = 'bad-unknown', priority = 2,
      text = 'Potentially Bad Traffic' },

    { name = 'attempted-recon', priority = 2,
      text = 'Attempted Information Leak' },

    { name = 'successful-recon-limited', priority = 2,
      text = 'Information Leak' },

    { name = 'successful-recon-largescale', priority = 2,
      text = 'Large Scale Information Leak' },

    { name = 'attempted-dos', priority = 2,
      text = 'Attempted Denial of Service' },

    { name = 'successful-dos', priority = 2,
      text = 'Denial of Service' },

    { name = 'attempted-user', priority = 1,
      text = 'Attempted User Privilege Gain' },

    { name = 'unsuccessful-user', priority = 1,
      text = 'Unsuccessful User Privilege Gain' },

    { name = 'successful-user', priority = 1,
      text = 'Successful User Privilege Gain' },

    { name = 'attempted-admin', priority = 1,
      text = 'Attempted Administrator Privilege Gain' },

    { name = 'successful-admin', priority = 1,
      text = 'Successful Administrator Privilege Gain' },

    { name = 'rpc-portmap-decode', priority = 2,
      text = 'Decode of an RPC Query' },

    { name = 'shellcode-detect', priority = 1,
      text = 'Executable code was detected' },

    { name = 'string-detect', priority = 3,
      text = 'A suspicious string was detected' },

    { name = 'suspicious-filename-detect', priority = 2,
      text = 'A suspicious filename was detected' },

    { name = 'suspicious-login', priority = 2,
      text = 'An attempted login using a suspicious username was detected' },

    { name = 'system-call-detect', priority = 2,
      text = 'A system call was detected' },

    { name = 'tcp-connection', priority = 4,
      text = 'A TCP connection was detected' },

    { name = 'trojan-activity', priority = 1,
      text = 'A Network Trojan was detected' },

    { name = 'unusual-client-port-connection', priority = 2,
      text = 'A client was using an unusual port' },

    { name = 'network-scan', priority = 3,
      text = 'Detection of a Network Scan' },

    { name = 'denial-of-service', priority = 2,
      text = 'Detection of a Denial of Service Attack' },

    { name = 'non-standard-protocol', priority = 2,
      text = 'Detection of a non-standard protocol or event' },

    { name = 'protocol-command-decode', priority = 3,
      text = 'Generic Protocol Command Decode' },

    { name = 'web-application-activity', priority = 2,
      text = 'Access to a potentially vulnerable web application' },

    { name = 'web-application-attack', priority = 1,
      text = 'Web Application Attack' },

    { name = 'misc-activity', priority = 3,
      text = 'Misc activity' },

    { name = 'misc-attack', priority = 2,
      text = 'Misc Attack' },

    { name = 'icmp-event', priority = 3,
      text = 'Generic ICMP event' },

    { name = 'inappropriate-content', priority = 1,
      text = 'Inappropriate Content was Detected' },

    { name = 'policy-violation', priority = 1,
      text = 'Potential Corporate Privacy Violation' },

    { name = 'default-login-attempt', priority = 2,
      text = 'Attempt to login by a default username and password' },

    { name = 'sdf', priority = 2,
      text = 'Sensitive Data' },

    { name = 'file-format', priority = 1,
      text = 'Known malicious file or file based exploit' },

    { name = 'malware-cnc', priority = 1,
      text = 'Known malware command and control traffic' },

    { name = 'client-side-exploit', priority = 1,
      text = 'Known client side exploit attempt' }
}

---------------------------------------------------------------------------
-- port_scan defaults
---------------------------------------------------------------------------

tcp_low_ports = { scans =   0, rejects =  5, nets =  25, ports =  5 }
tcp_low_decoy = { scans =   0, rejects = 15, nets =  50, ports = 30 }
tcp_low_sweep = { scans =   0, rejects =  5, nets =   5, ports = 15 }
tcp_low_dist =  { scans =   0, rejects = 15, nets =  50, ports = 15 }

tcp_med_ports = { scans = 200, rejects = 10, nets =  60, ports = 15 }
tcp_med_decoy = { scans = 200, rejects = 30, nets = 120, ports = 60 }
tcp_med_sweep = { scans =  30, rejects =  7, nets =   7, ports = 10 }
tcp_med_dist =  { scans = 200, rejects = 30, nets = 120, ports = 30 }

tcp_hi_ports =  { scans = 200, rejects =  5, nets = 100, ports = 10 }
tcp_hi_decoy =  { scans = 200, rejects =  7, nets = 200, ports = 60 }
tcp_hi_sweep =  { scans =  30, rejects =  3, nets =   3, ports = 10 }
tcp_hi_dist =   { scans = 200, rejects =  5, nets = 200, ports = 10 }

udp_low_ports = { scans =   0, rejects =  5, nets =  25, ports =  5 }
udp_low_decoy = { scans =   0, rejects = 15, nets =  50, ports = 30 }
udp_low_sweep = { scans =   0, rejects =  5, nets =   5, ports = 15 }
udp_low_dist =  { scans =   0, rejects = 15, nets =  50, ports = 15 }

udp_med_ports = { scans = 200, rejects = 10, nets =  60, ports = 15 }
udp_med_decoy = { scans = 200, rejects = 30, nets = 120, ports = 60 }
udp_med_sweep = { scans =  30, rejects =  5, nets =   5, ports = 20 }
udp_med_dist =  { scans = 200, rejects = 30, nets = 120, ports = 30 }

udp_hi_ports =  { scans = 200, rejects =  3, nets = 100, ports = 10 }
udp_hi_decoy =  { scans = 200, rejects =  7, nets = 200, ports = 60 }
udp_hi_sweep =  { scans =  30, rejects =  3, nets =   3, ports = 10 }
udp_hi_dist =   { scans = 200, rejects =  3, nets = 200, ports = 10 }

ip_low_proto =  { scans =   0, rejects = 10, nets =  10, ports = 50 }
ip_low_decoy =  { scans =   0, rejects = 40, nets =  50, ports = 25 }
ip_low_sweep =  { scans =   0, rejects = 10, nets =  10, ports = 10 }
ip_low_dist =   { scans =   0, rejects = 15, nets =  25, ports = 50 }

ip_med_proto =  { scans = 200, rejects = 10, nets =  10, ports = 50 }
ip_med_decoy =  { scans = 200, rejects = 40, nets =  50, ports = 25 }
ip_med_sweep =  { scans =  30, rejects = 10, nets =  10, ports = 10 }
ip_med_dist =   { scans = 200, rejects = 15, nets =  25, ports = 50 }

ip_hi_proto =   { scans = 200, rejects =  3, nets =   3, ports = 10 }
ip_hi_decoy =   { scans = 200, rejects =  7, nets =  15, ports =  5 }
ip_hi_sweep =   { scans =  30, rejects =  3, nets =   3, ports =  7 }
ip_hi_dist =    { scans = 200, rejects =  3, nets =  11, ports = 10 }

icmp_low_sweep = { scans =   0, rejects =  5, nets =   5, ports =  5 }
icmp_med_sweep = { scans =  20, rejects =  5, nets =   5, ports =  5 }
icmp_hi_sweep =  { scans =  10, rejects =  3, nets =   3, ports =  5 }

default_hi_port_scan =
{
    protos = 'all',
    scan_types = 'all',

    tcp_window = 600,
    udp_window = 600,
    ip_window = 600,
    icmp_window = 600,

    tcp_ports = tcp_hi_ports,
    tcp_decoy = tcp_hi_decoy,
    tcp_sweep = tcp_hi_sweep,
    tcp_dist = tcp_hi_dist,

    udp_ports = udp_hi_ports,
    udp_decoy = udp_hi_decoy,
    udp_sweep = udp_hi_sweep,
    udp_dist = udp_hi_dist,

    ip_proto = ip_hi_proto,
    ip_decoy = ip_hi_decoy,
    ip_sweep = ip_hi_sweep,
    ip_dist = ip_hi_dist,

    icmp_sweep = icmp_hi_sweep,
}

default_med_port_scan =
{
    protos = 'all',
    scan_types = 'all',

    tcp_window = 90,
    udp_window = 90,
    ip_window = 90,
    icmp_window = 90,

    tcp_ports = tcp_med_ports,
    tcp_decoy = tcp_med_decoy,
    tcp_sweep = tcp_med_sweep,
    tcp_dist = tcp_med_dist,

    udp_ports = udp_med_ports,
    udp_decoy = udp_med_decoy,
    udp_sweep = udp_med_sweep,
    udp_dist = udp_med_dist,

    ip_proto = ip_med_proto,
    ip_decoy = ip_med_decoy,
    ip_sweep = ip_med_sweep,
    ip_dist = ip_med_dist,

    icmp_sweep = icmp_med_sweep,
}

default_low_port_scan =
{
    protos = 'all',
    scan_types = 'all',

    tcp_window = 60,
    udp_window = 60,
    ip_window = 60,
    icmp_window = 60,

    tcp_ports = tcp_low_ports,
    tcp_decoy = tcp_low_decoy,
    tcp_sweep = tcp_low_sweep,
    tcp_dist = tcp_low_dist,

    udp_ports = udp_low_ports,
    udp_decoy = udp_low_decoy,
    udp_sweep = udp_low_sweep,
    udp_dist = udp_low_dist,

    ip_proto = ip_low_proto,
    ip_decoy = ip_low_decoy,
    ip_sweep = ip_low_sweep,
    ip_dist = ip_low_dist,

    icmp_sweep = icmp_low_sweep,
}

---------------------------------------------------------------------------
-- default js_norm configuration
---------------------------------------------------------------------------

-- ECMAScript Standard Built-in Objects and Functions Names (Identifiers)
-- Also, might include other non-specification identifiers like those
-- are part of WebAPI or frameworks

default_js_norm_ident_ignore =
{
    -- GlobalObject.Functions
    'eval', 'PerformEval', 'HostEnsureCanCompileStrings', 'EvalDeclarationInstantiation',
    'isFinite', 'isNaN', 'parseFloat', 'parseInt', 'Encode', 'Decode', 'decodeURI',
    'decodeURIComponent', 'encodeURI', 'encodeURIComponent',

    -- Microsoft.JScript.GlobalObject.Functions
    'CollectGarbage', 'GetHashCode', 'GetObject', 'GetType', 'MemberwiseClone',

    -- GlobalObject.Constructors
    'AggregateError', 'Array', 'ArrayBuffer', 'BigInt', 'BitInt64Array', 'BigUint64Array',
    'Boolean', 'DataView', 'Date', 'Error', 'EvalError', 'FinalizationRegistry',
    'Float32Array', 'Float64Array', 'Function', 'Int8Array', 'Int16Array', 'Int32Array',
    'Map', 'NativeError', 'Number', 'Object', 'Promise', 'Proxy',
    'RangeError', 'ReferenceError', 'RegExp', 'Set', 'SharedArrayBuffer', 'String',
    'Symbol', 'SyntaxError', 'TypeError', 'Uint8Array', 'Uint8ClampedArray', 'Uint16Array',
    'Uint32Array', 'URIError', 'WeakMap', 'WeakRef', 'WeakSet',

    -- Microsoft.JScript.GlobalObject.Constructors
    'ActiveXObject', 'Enumerator', 'VBArray',

    -- Atomics
    'Atomics', 'WaiterList', 'ValidateIntegerTypedArray', 'ValidateAtomicAccess', 'GetWaiterList',
    'EnterCriticalSection', 'LeaveCriticalSection', 'AddWaiter', 'RemoveWaiter', 'RemoveWaiters',
    'SuspendAgent', 'NotifyWaiter', 'AtomicReadModifyWrite', 'ByteListBitwiseOp', 'ByteListEqual',

    -- JSON
    'JSON', 'InternalizeJSONProperty', 'SerializeJSONProperty', 'QuoteJSONString', 'UnicodeEscape',
    'SerializeJSONObject','SerializeJSONArray',

    -- Math
    'Math',

    -- Reflect
    'Reflect',

    -- Date and Time
    'LocalTZA', 'LocalTime', 'UTC', 'MakeTime', 'MakeDay', 'MakeDate', 'TimeClip', 'TimeString',
    'DateString', 'TimeZoneString', 'ToDateString',

    -- String
    'StringPad', 'GetSubstitution', 'SplitMatch', 'TrimString',

    -- RegExp
    'RegExpExec', 'RegExpBuiltinExec', 'AdvanceStringIndex', 'RegExpHasFlag',

    -- TypedArray
    'TypedArray', 'TypedArraySpeciesCreate', 'TypedArrayCreate', 'ValidateTypedArray',
    'AllocateTypedArray', 'InitializeTypedArrayFromTypedArray',
    'InitializeTypedArrayFromArrayBuffer', 'InitializeTypedArrayFromList',
    'InitializeTypedArrayFromArrayLike', 'AllocateTypedArrayBuffer',

    -- ArrayBuffer
    'AllocateArrayBuffer', 'IsDetachedBuffer', 'DetachArrayBuffer', 'CloneArrayBuffer',
    'IsUnsignedElementType', 'IsUnclampedIntegerElementType', 'IsBigIntElementType',
    'IsNoTearConfiguration', 'RawBytesToNumeric', 'GetValueFromBuffer', 'NumericToRawBytes',
    'SetValueInBuffer', 'GetModifySetValueInBuffer',

    -- SharedArrayBuffer
    'AllocateSharedArrayBuffer', 'IsSharedArrayBuffer',

    -- DataView
    'GetViewValue', 'SetViewValue', 'getDataView',

    -- WeakRef
    'WeakRefDeref',

    -- Promise
    'IfAbruptRejectPromise', 'CreateResolvingFunctions', 'FulfillPromise', 'NewPromiseCapability',
    'IsPromise', 'RejectPromise', 'TriggerPromiseReactions', 'HostPromiseRejectionTracker',
    'NewPromiseReactionJob', 'NewPromiseResolveThenableJob', 'GetPromiseResolve',
    'PerformPromiseAll', 'PerformPromiseAllSettled', 'PerformPromiseAny', 'PerformPromiseRace',
    'PromiseResolve', 'PerformPromiseThen',

    -- GeneratorFunction
    'GeneratorFunction', 'AsyncGeneratorFunction',

    -- Generator
    'Generator', 'GeneratorStart', 'GeneratorValidate', 'GeneratorResume', 'GeneratorResumeAbrupt',
    'GetGeneratorKind', 'GeneratorYield', 'Yield', 'CreateIteratorFromClosure',

    -- AsyncGenerator
    'AsyncGenerator', 'AsyncGeneratorStart', 'AsyncGeneratorValidate', 'AsyncGeneratorResolve',
    'AsyncGeneratorReject', 'AsyncGeneratorResumeNext', 'AsyncGeneratorEnqueue',
    'AsyncGeneratorYield', 'CreateAsyncIteratorFromClosure',

    -- AsyncFunction
    'AsyncFunction', 'AsyncFunctionStart',

    -- WebAPI
    'console', 'document',

    -- Misc
    'arguments', 'CreateDynamicFunction', 'HostHasSourceTextAvailable', 'SymbolDescriptiveString',
    'IsConcatSpreadable', 'FlattenIntoArray', 'SortCompare', 'AddEntriesFromIterable',
    'CreateMapIterator', 'CreateSetIterator', 'EventSet', 'SharedDataBlockEventSet',
    'HostEventSet', 'ComposeWriteEventBytes', 'ValueOfReadEvent', 'escape', 'unescape',
    'CreateHTML',

    -- Adobe Acrobat
    'addAnnot', 'bookmarkRoot', 'calculateNow', 'closeDoc', 'createDataObject', 'docID',
    'exportAsFDF', 'exportAsFDFStr', 'getAnnotRichMedia', 'getAnnots', 'getAnnotsRichMedia',
    'getField', 'getLegalWarnings', 'getNthFieldName', 'getOCGs', 'openDataObject', 'removeField',
    'removeLinks', 'modDate', 'scroll', 'setAction', 'setPageAction', 'submitForm', 'syncAnnotScan',
    'Collab', 'Net', 'Rendition', 'XFA', 'XMLData', 'app', 'catalog', 'event', 'spell', 'util'
}

default_js_norm_prop_ignore =
{
    -- Object
    'constructor', 'prototype', '__proto__', '__defineGetter__', '__defineSetter__',
    '__lookupGetter__', '__lookupSetter__', '__count__', '__noSuchMethod__', '__parent__',
    'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString',
    'toSource', 'valueOf', 'getNotifier', 'eval', 'observe', 'unobserve', 'watch', 'unwatch',

    -- Function
    'arguments', 'arity', 'caller', 'length', 'name', 'displayName', 'apply', 'bind', 'call',
    'isGenerator',

    -- Number
    'toExponential', 'toFixed', 'toPrecision',

    -- String
    'at', 'charAt', 'charCodeAt', 'codePointAt', 'concat', 'includes', 'endWith', 'indexOf',
    'lastIndexOf', 'localeCompare', 'match', 'matchAll', 'normalize', 'padEnd', 'padStart',
    'repeat', 'replace', 'replaceAll', 'search', 'slice', 'split', 'startsWith', 'substring',
    'toLocaleLowerCase', 'toLocaleUpperCase', 'toLowerCase', 'toUpperCase', 'trim', 'trimStart',
    'trimEnd',

    -- RegExp
    'flags', 'dotAll', 'global', 'hasIndices', 'ignoreCase', 'multiline', 'source', 'sticky',
    'unicode', 'lastIndex', 'compile', 'exec', 'test', 'input', 'lastMatch', 'lastParen',
    'leftContext', 'rightContext',

    -- Array
    'copyWithin', 'entries', 'every', 'fill', 'filter', 'find', 'findIndex', 'flat', 'flatMap',
    'forEach', 'groupBy', 'groupByToMap', 'join', 'keys', 'map', 'pop',  'push', 'reduce',
    'reduceRight', 'reverse', 'shift', 'unshift', 'some', 'sort', 'splice',

    -- Generator
    'next', 'return', 'throw',

    -- EventTarget
    'addEventListener', 'dispatchEvent', 'removeEventListener',

    -- Node
    'childNodes', 'nodeValue', 'ownerDocument', 'parentElement', 'textContent', 'appendChild',
    'cloneNode', 'insertBefore', 'removeChild', 'replaceChild',

    -- Element
    'innerHTML', 'msRegionOverflow', 'openOrClosedShadowRoot', 'outerHTML', 'part', 'shadowRoot',
    'after', 'append', 'attachShadow', 'before', 'closest', 'createShadowRoot', 'getAttribute',
    'getAttributeNode', 'getAttributeNodeNS', 'getAttributeNS', 'getElementsByClassName',
    'getElementsByTagName', 'getElementsByTagNameNS', 'insertAdjacentElement', 'insertAdjacentHTML',
    'insertAdjacentText', 'prepend', 'querySelector', 'querySelectorAll', 'releasePointerCapture',
    'remove', 'removeAttribute', 'removeAttributeNode', 'removeAttributeNS', 'replaceChildren',
    'replaceWith', 'setAttribute', 'setAttributeNode', 'setAttributeNodeNS', 'setAttributeNS',
    'setCapture', 'setHTML', 'setPointerCapture', 'toggleAttribute',

    -- HTMLElement
    'contentEditable', 'contextMenu', 'dataset', 'dir', 'enterKeyHint', 'hidden', 'inert',
    'innerText', 'lang', 'nonce', 'outerText', 'style', 'tabIndex', 'title',
    'attachInternals',

    -- Promise
    'catch', 'finally',

    -- Misc
    'ExportStyle', 'callee',

    -- Adobe Acrobat
    'activated', 'addAnnot', 'addLink', 'annot', 'attachIcon', 'begin', 'bookmarkRoot',
    'borderColor', 'borderStyle', 'buttonGetIcon', 'calculate', 'calculateNow', 'callAS',
    'children', 'close', 'closeDoc', 'commitOnSelChange', 'createChild', 'createDataObject', 'data',
    'dataObjects', 'destroy', 'doc', 'docID', 'end', 'execute', 'exportAsFDF', 'exportAsFDFStr',
    'exportDataObject', 'exportValues', 'get', 'getAnnot', 'getAnnots', 'getAnnotsRichMedia',
    'getField', 'getLegalWarnings', 'getNthFieldName', 'getOCGs', 'getPageBox', 'openDataObject',
    'getProps', 'inReplyTo', 'layout', 'media', 'modDate', 'newPlayer', 'objectMetadata', 'page',
    'point', 'points', 'popupOpen', 'popupRect', 'print', 'println', 'qSilence', 'query', 'rect',
    'removeField', 'removeLinks', 'reset', 'resetForm', 'richText', 'rotate', 'saveAs', 'scroll',
    'setAction', 'setFocus', 'setIntent', 'setItems', 'setPageAction', 'setPersistent', 'setProps',
    'show', 'state', 'stateModel', 'streamFromString', 'stringFromStream', 'submitForm',
    'syncAnnotScan', 'talk', 'text', 'toggleNoView', 'type', 'userName', 'value', 'width', 'xfa'
}

default_js_norm =
{
    -- params not specified here get internal defaults
    ident_ignore = default_js_norm_ident_ignore,
    prop_ignore = default_js_norm_prop_ignore,
}

---------------------------------------------------------------------------
-- default whitelist
---------------------------------------------------------------------------
default_whitelist =
[[
    default_wizard
    default_references default_classifications gtp_v0_msg gtp_v1_msg gtp_v2_msg
    gtp_v0_info gtp_v1_info gtp_v2_info default_gtp tcp_low_ports
    tcp_low_decoy tcp_low_sweep tcp_low_dist tcp_med_ports
    tcp_med_decoy tcp_med_sweep tcp_med_dist tcp_hi_ports tcp_hi_decoy
    tcp_hi_sweep tcp_hi_dist udp_low_ports udp_low_decoy udp_low_sweep
    udp_low_dist udp_med_ports udp_med_decoy udp_med_sweep udp_med_dist
    udp_hi_ports udp_hi_decoy udp_hi_sweep udp_hi_dist ip_low_proto
    ip_low_decoy ip_low_sweep ip_low_dist ip_med_proto ip_med_decoy
    ip_med_sweep ip_med_dist ip_hi_proto ip_hi_decoy ip_hi_sweep
    ip_hi_dist icmp_low_sweep icmp_med_sweep icmp_hi_sweep
    default_hi_port_scan default_med_port_scan default_low_port_scan
    default_variables netflow_versions default_js_norm_ident_ignore
    default_js_norm_prop_ignore default_js_norm
]]

snort_whitelist_append(default_whitelist)
