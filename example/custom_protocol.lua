do
    -- load library to generate dissector
    if not pcall(dofile, Dir.personal_plugins_path()..'/lib-ws-dissector.lua') then
        assert(pcall(dofile, Dir.global_plugins_path()..'/lib-ws-dissector.lua'), "Could not load lib-ws-dissector.lua!")
    end
    
    -- mapping
    local type_map = {
        [0x00000000] = "Request",
        [0x00000001] = "Response",
    }

    -- defining protocol header
    local header_config = {
        name = 'custom_protocol',
        description = 'Custom Protocol',
        port_filter = {
            protocol = 'udp',
            range = '40000-41000',
            description = 'Custom Protocol Port Range',
            max_value = 65535
        },
        pre_init = function(config)
            print("[OPTIONAL] You can access and modify the config here before anything is done.")
        end,
        pre_parse = function(config, protocol, table) 
            print("[OPTIONAL] You can access config, protocol and table here before fields are generated.") 
        end,
        post_parse = function(config, protocol, table) 
            print("[OPTIONAL] You can access config, protocol and table after all fields are generated. "..
                  "All ProtoField objects are stored in the associated 'spec' entry in the table property "..
                  "'proto_field'. It's a table containing all generated fields.")
        end,
        pre_dissection = function(config, protocol, buffer, pinfo, tree) 
            print("[OPTIONAL] You can access the config, protocol and buffer, pinfo and tree object of each "..
                  "payload here before any dissection happened.") 
        end,
        key = { name = 'type', type_id = typeid.BE_UINT32 },
        spec = {
            { type_id = typeid.LE_UINT16, name = 'Length', abbr = 'length', base = base.DEC },
            { type_id = typeid.COMPOSITE, abbr = 'flag_fields', sub_spec = {
                { type_id = typeid.BITMASK32, abbr = 'bitmask', sub_spec = {
                    { type_id = typeid.BE_UINT32, name = 'SomeFlag', abbr = 'some_flag', mask = 0xFFFF, base = base.DEC },
                    { type_id = typeid.BE_UINT32, name = 'OtherFlag', abbr = 'other_flag', mask = 0x01, base = base.DEC },
                } },
                { type_id = typeid.UINT8, name = 'SomeByte', abbr = 'byte', base = base.DEC },
                { type_id = typeid.COMPOSITE, abbr = 'composition', sub_spec = {
                    { type_id = typeid.UINT8, name = 'SomeValue', abbr = 'other_value', base = base.DEC },
                    { type_id = typeid.UINT8, name = 'OtherValue', abbr = 'some_value', base = base.DEC },
                } },
            } },
            { is_key = true, type_id = typeid.BE_UINT32, name = 'Type', abbr = 'type', base = base.DEC, valuestring = type_map },
        }
    }

    -- generating dissector
    generate_dissector(header_config)

    -- defining protocol payload
    local payload_config = {
        name ='custom_protocol.payload',
        description = 'Custom Protocol Payload',
        after = { 
            name = 'custom_protocol',
            key = 'type',
            value = 1
        },
        spec = {
            { type_id = typeid.BE_UINT16, name = 'StrLen', abbr = 'string_size', base = base.DEC },
            { type_id = typeid.STRINGZ, size = 'string_size', name = "Text", abbr = 'string' },
        }
    }

    -- generating dissector
    generate_dissector(payload_config)

end
