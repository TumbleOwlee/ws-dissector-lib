# Wireshark Dissector Library
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/TumbleOwlee/ws-dissector-lib/blob/master/LICENSE)

## What is it?
This library provides an abstraction to generate [Wireshark](https://wireshark.com/) dissectors based on a given configuration. It allows fast prototyping of custom protocol dissectors with support of dissector chaining. It arises from the need for working dissectors without a guarantee of stable procotol specifications in the workplace.

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
    -- [OPTIONAL] callback to modify the config on initialization 
    pre_init = function(config) end,
    -- [OPTIONAL] callback to access the config, protocol (Proto) and table (DissectorTable)
    pre_parse = function(config, protocol, table) end,
    -- [OPTIONAL] callback to access the config, protocol and table after creation of all ProtoFields
    -- the generated ProtoField instances can be accessed in the associated item in the table 'proto_fields'
    post_parse = function(config, protocol, table) end,
    -- [OPTIONAL] callback to access the data before dissection as given by wireshark.
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
    -- abbreviation (see 11.6.7.1)
    abbr = 'some_abbr',
    -- base (see 11.6.7.1) (unused by BITMASK and COMPOSITE)
    base = base.HEX,
    -- mask (see 11.6.7.1) (unused by BITMASK and COMPOSITE)
    mask = 0xFFFF,
    -- size of the field in bytes (only necessary if type size is not defined (ex. strings))
    -- can also be used to override predefined sizes, for example to only read 5 bytes instead of 8 for UINT64
    size = 10,
    -- also possible if another field with abbr == 'type' exists to allow dynamic size on dissection
    size = 'type',
    -- maximal repititions of this field. if size is set, this is the upper bound
    max_reps = 10,
    -- mapping table (see 11.6.7.1) (unused by BITMASK and COMPOSITE)
    valuestring = {},
    -- sub fields, only for BITMASK and COMPOSITE
    sub_spec = {
        ...
    }
}
```
The special type *COMPOSITE* will create a substructure and allows to repeat a substructure multiple times. Each repitition will consume its own bytes. In comparison, all fields stored in the special structures *BITMASK*, *BITMASK16*, *BITMASK24*, *BITMASK32* and *BITMASK64* will get the same bytes. So, a *COMPOSITE* of four *BE_UINT32* will consume 16 bytes, but a *BITMASK32* of four *BE_UINT32* will only consume 4 bytes. Normally, a *BITMASKXX* will only contain fields of type *BE_UINTXX*.

## Usage
At first, you have to create a configuration as shown in section **Configuration**. Afterwards just pass the table to the provided generator. 
```lua
generate_dissector(config)
```
Now everything is handled for you. Just reload or restart Wireshark and you are good to go.
