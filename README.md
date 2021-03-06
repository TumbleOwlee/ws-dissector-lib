# Wireshark Dissector Library
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/TumbleOwlee/ws-dissector-lib/blob/master/LICENSE)

## What is it?
This library provides an abstraction to generate [Wireshark](https://wireshark.com/) dissectors based on a given configuration. It allows fast prototyping of custom protocol dissectors with support of dissector chaining. It arises from the need for working dissectors without a guarantee of stable protocol specifications in the workplace.

## Alternatives
I stumbled over the following alternatives. You can check them out and make a choice afterwards.
* [Wireshark Generic Dissector](http://wsgd.free.fr/index.html)
* [CSjark](https://csjark.readthedocs.io/en/latest/user/intro.html)

## WARNING
This library is still in the *very* early stage of development and only a side project. Most features are supported for simple types like (unsigned) integer, string, bitmasks and compositions. Additional types like ipv4 and ipv6 with fixed sizes should also work. Special types like GUID are not tested and thus can be broken. Some types, such as RELATIVE_TIME, do not have predefined sizes at the moment, therefore if you encounter any dissector failures, try setting the size property to override defaults.

## Goals
* **Simple**: Offer a simple configuration for complex protocols
* **Productive**: Changes to a protocol specification can be quickly applied

## Getting started
Copy the provided [ws-dissector-lib.lua](https://github.com/TumbleOwlee/ws-dissector-lib/blob/master/lib-ws-dissector.lua) into your global or your personal plugin directory. The locations of the plugin directories on your system can be retrieved by opening Wireshark and navigating to **Tools/About Wireshark/Folders**. If you are running Wireshark as root, make sure to not use your user's personal plugin directory.

Now, to be able to use the provided library in your custom dissector, add the following lines to your dissector:
```lua
    -- load library to generate dissector
    if not pcall(dofile, Dir.personal_plugins_path()..'/lib-ws-dissector.lua') then
        assert(pcall(dofile, Dir.global_plugins_path()..'/lib-ws-dissector.lua'), "Could not load lib-ws-dissector.lua!")
    end
```
It will automatically load the library from your personal or global plugin directory. If you place the library or any dissector into some subdirectory, you will have to modify the search paths accordingly.

### Example
A working example is provided in [custom_protocol.lua](https://github.com/TumbleOwlee/ws-dissector-lib/blob/master/example/custom_protocol.lua). Just place it into your plugin folder and restart Wireshark or press *Ctrl + Shift + L* to reload all plugins. Now use a tool of your choice to send some bytes. On Linux you could use *echo* and *netcat* for this purpose.
```bash
echo -n -e "\x01\x02\x03\x01\x02\x03\x00\x00\00\x00\x00\x00\x01\x00\x0CHello World!" | netcat -u -p 40400 <IP> 40100
```
By adding the protocol filter 'custom_protocol' the message should appear and every field, including the text with variable length, shall be correctly displayed.

## Configuration
For the base setup, the library uses the same property names as defined in the [Wireshark Documentation](https://www.wireshark.org/docs/wsdg_html_chunked/index.html). Additional properties are added to support various features, like replicating a given field multiple times. The configuration consists of the following properties:
```lua
config = {
    -- protocol name (see 11.6.5.1) 
    name = 'protocol',
    -- protocol description  (see 11.6.5.1)
    description = 'description',
    -- the label of the protocol tree can be set
    label = 'custom tree label of the protocol',
    -- it can also be a function, the whole payload buffer is given as input
    label = function(buffer) return "The first byte is "..buffer(0,1):uint() end,
    -- [OPTIONAL] filter 
    port_filter = {
        -- protocol 
        protocol = 'udp',
        -- range (see 11.6.3.7)
        range = '40000-41000',
        -- description (see 11.6.3.7)
        description = 'Some description',
        -- maximum value (see 11.6.3.7)
        max_value = 65535
    }
    -- if set, this dissector will pass the parent tree node to chained dissectors instead of itself.
    -- This way chained dissectors are not displayed as subtrees
    pass_root = true,
    -- allows to customize the text written to pinfo.cols.info
    col_info = function(buffer) end,
    -- [OPTIONAL] callback to modify the config on initialization 
    pre_init = function(config) end,
    -- [OPTIONAL] callback to access the config, protocol (Proto) and table (DissectorTable)
    pre_parse = function(config, protocol, table) end,
    -- [OPTIONAL] callback to access the config, protocol and table after creation of all ProtoFields
    -- the generated ProtoField instances can be accessed in the associated item in the table 'proto_fields'
    post_parse = function(config, protocol, table) end,
    -- [OPTIONAL] callback to access the data upfront and customize the choice to drop it or not
    -- this function has to return true to allow dissection, else it is dropped
    pre_dissection = function(config, protocol, buffer, pinfo, tree) end,
    -- [OPTIONAL] only necessary if dissector depends on another dissector
    after = {
        -- name of the dissector that has to be executed first
        name = 'some_other_dissector',
        -- key name of the other dissector
        key = 'type',
        -- the value that the key has to have to activate this dissector
        value = 1
    },
    -- [OPTIONAL] key definition to allow dissector chaining
    key = {
        -- name of the key
        name = 'type',
        -- type of the key
        type_id = typeid.BE_UINT32
    }
    -- specification of all fields
    spec = {
        ...
    }
}
```
Each field entry in `spec` has various properties that depend on the given field type (see chapter [11.6.7.1](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField)). The full list is given in this example.
```lua
field = {
    -- the type of the fields (see lib-ws-dissector.lua for the full list)
    type_id = typeid.UINT32,
    -- name (see 11.6.7.1) (in case of BITMASK and COMPOSITE only necessary if subtree shall be created)
    name = 'SomeName',
    -- name can also be a function - the buffer of the field is given as input
    name = function(buffer) if buffer:uint() == 1 then return "TRUE" else "FALSE" end,
    -- abbreviation (see 11.6.7.1) (can be omitted for BITMASK and COMPOSITE)
    abbr = 'some_abbr',
    -- to skip some bytes or to jump to the last x bytes because of checksum negative values will result 
    -- in jump to the last minus x byte this setting is only allowed once - the skipped bytes will be 
    -- forwarded to the chained dissector instead of the remaining bytes
    offset = -8,
    -- positive values will just result in a simple skip of the next x bytes
    offset = 20,
    -- base (see 11.6.7) (unused by BITMASK and COMPOSITE)
    base = base.HEX,
    -- some ProtoField use 'display' to specify the base value (see 11.6.7) 
    display = base.DASH,
    -- mask (see 11.6.7) (unused by BITMASK and COMPOSITE)
    mask = 0xFFFF,
    -- size of the field in bytes (only necessary if type size is not defined (ex. strings))
    -- can also be used to override predefined sizes, for example to only read 5 bytes instead of 8 for UINT64
    size = 10,
    -- also possible if another field with abbr == 'type' exists to allow dynamic size on dissection
    size = 'type',
    -- maximal repetitions of this field
    max_reps = 10,
    -- if actual number of repetitions depend on a given field, it can be linked and at dissection only
    -- so many repetitions as given by the value of the field are dissected
    rep_dep = 'type',
    -- mapping table (see 11.6.7.1) (unused by BITMASK and COMPOSITE but also supported for STRING and STRINGZ)
    valuestring = {},
    -- defines whether the field is the key or not (only supported for integer and string types)
    is_key = true,
    -- define a custom function to do with the buffer what ever you want
    mapping = function(buffer) return buffer:string() end,
    -- subfields, only for BITMASK and COMPOSITE
    sub_spec = {
        ...
    }
}
```
The possible field types are given by the predefined typeid table
```lua
 typeid = {
        COMPOSITE  =  1, CHAR          =  2, UINT8         =  3, LE_UINT16 =  4, BE_UINT16 =  5, 
        LE_UINT24  =  6, BE_UINT24     =  7, LE_UINT32     =  8, BE_UINT32 =  9, LE_UINT64 = 10, 
        BE_UINT64  = 11, INT8          = 12, LE_INT16      = 13, BE_INT16  = 14, LE_INT24  = 15,
        BE_INT24   = 16, LE_INT32      = 17, BE_INT32      = 18, LE_INT64  = 19, BE_INT64  = 20,
        BOOL       = 21, ABSOLUTE_TIME = 22, RELATIVE_TIME = 23, FLOAT     = 24, DOUBLE    = 25,
        STRING     = 26, STRINGZ       = 27, BYTES         = 28, UBYTES    = 29, NONE      = 30,
        IPV4       = 31, IPV6          = 32, ETHER         = 33, GUID      = 34, OID       = 35,
        PROTOCOL   = 36, REL_OID       = 37, SYSTEMID      = 38, EUID64    = 39, BITMASK   = 40,
        BITMASK16  = 41, BITMASK24     = 42, BITMASK32     = 43, BITMASK64 = 44,
    }
```
The special type *COMPOSITE* will create a substructure and allows to repeat a substructure multiple times. Each repetition will consume its own bytes. In comparison, all fields stored in the special structures *BITMASK*, *BITMASK16*, *BITMASK24*, *BITMASK32* and *BITMASK64* will get the same bytes. So, a *COMPOSITE* of four *BE_UINT32* will consume 16 bytes, but a *BITMASK32* of four *BE_UINT32* will only consume 4 bytes. Normally, a *BITMASKXX* will only contain fields of type *BE_UINTXX*.

## Usage
At first, you have to create a configuration as shown in section **Configuration**. Afterwards just pass the table to the provided generator. 
```lua
generate_dissector(config)
```
Now everything is handled for you. Just reload or restart Wireshark and you are good to go.
