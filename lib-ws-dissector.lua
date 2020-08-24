do
    -- Enumeration type of type ids
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

    local function typeid_to_ftype(id)
        if (id == typeid.LE_UINT32) or (id == typeid.BE_UINT32) then
            return ftypes.UINT32
        elseif (id == typeid.LE_UINT24) or (id == typeid.BE_UINT24) then
            return ftypes.UINT24
        elseif (id == typeid.LE_UINT16) or (id == typeid.BE_UINT16) then
            return ftypes.UINT16
        elseif id == typeid.UINT8 then
            return ftypes.UINT8
        elseif id == typeid.STRING then
            return ftypes.STRING
        else
            error("Please check key type! Only UINT8, LE_UINT16, BE_UINT16, LE_UINT24, BE_UINT24, LE_UINT32, BE_UINT32 and STRING are supported.")
        end
    end

    local function typeid_to_value(id, buffer)
        if id == typeid.LE_UINT16 or id == typeid.LE_UINT24 or id == typeid.LE_UINT32 then
            return buffer:le_uint()
        elseif id == typeid.UINT8 or id == typeid.BE_UINT16 or id == typeid.BE_UINT24 or id == typeid.BE_UINT32 then
            return buffer:uint()
        elseif id == typeid.STRING then
            return buffer:string()
        elseif id == typeid.STRINGZ then
            return buffer:stringz()
        else
            error("Please check key type! Only UINT8, LE_UINT16, BE_UINT16, LE_UINT24, BE_UINT24, LE_UINT32, BE_UINT32 and STRING are supported.")
        end
    end

    local function create_protofield(prefix, field_spec)
        local abbr = prefix..'.'..field_spec.abbr
        local id = field_spec.type_id
        if id == typeid.CHAR then 
            return ProtoField.char(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.UINT8 then
            return ProtoField.uint8(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_UINT16 or id == typeid.BE_UINT16 then
            return ProtoField.uint16(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_UINT24 or id == typeid.BE_UINT24 then
            return ProtoField.uint24(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_UINT32 or id == typeid.BE_UINT32 then
            return ProtoField.uint32(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_UINT64 or id == typeid.BE_UINT64 then
            return ProtoField.uint64(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.INT8 then
            return ProtoField.int8(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_INT16 or id == typeid.BE_INT16 then
            return ProtoField.int16(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_INT24 or id == typeid.BE_INT24 then
            return ProtoField.int24(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_INT32 or id == typeid.BE_INT32 then
            return ProtoField.int32(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.LE_INT64 or id == typeid.BE_INT64 then
            return ProtoField.int64(abbr, field_spec.name, field_spec.base, field_spec.valuestring, field_spec.mask, field_spec.desc)
        elseif id == typeid.BOOL then
            return ProtoField.bool(abbr, field_spec.name, field_spec.base, field_spec.desc)
        elseif id == typeid.ABSOLUTE_TIME then
            return ProtoField.absolute_time(abbr, field_spec.name, field_spec.base, field_spec.desc)
        elseif id == typeid.RELATIVE_TIME then
            return ProtoField.relative_time(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.FLOAT then
            return ProtoField.float(abbr, field_spec.name, field_spec.valuestring, field_spec.desc)
        elseif id == typeid.DOUBLE then
            return ProtoField.double(abbr, field_spec.name, field_spec.valuestring, field_spec.desc)
        elseif id == typeid.STRING then
            if field_spec.valuestring and not field_spec.mapping then field_spec.mapping = field_spec.valuestring end
            return ProtoField.string(abbr, field_spec.name, field_spec.display, field_spec.desc)
        elseif id == typeid.STRINGZ then
            if field_spec.valuestring and not field_spec.mapping then field_spec.mapping = field_spec.valuestring end
            return ProtoField.stringz(abbr, field_spec.name, field_spec.display, field_spec.desc)
        elseif id == typeid.BYTES then
            return ProtoField.bytes(abbr, field_spec.name, field_spec.display, field_spec.desc)
        elseif id == typeid.UBYTES then
            return ProtoField.ubytes(abbr, field_spec.name, field_spec.display, field_spec.desc)
        elseif id == typeid.NONE then
            return ProtoField.none(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.IPV4 then
            return ProtoField.ipv4(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.IPV6 then
            return ProtoField.ipv6(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.ETHER then
            return ProtoField.ether(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.GUID then
            return ProtoField.guid(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.OID then
            return ProtoField.oid(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.PROTOCOL then
            return ProtoField.protocol(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.REL_OID then
            return ProtoField.rel_oid(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.SYSTEMID then
            return ProtoField.systemid(abbr, field_spec.name, field_spec.desc)
        elseif id == typeid.EUID64 then
            return ProtoField.euid64 (abbr, field_spec.name, field_spec.desc)
        else
            error("Please check type ids! The property 'type_id' contains undefined value.")
        end
    end

    local function parse_specification(protocol, prefix, spec)
        for k, v in pairs(spec) do
            if v.type_id == typeid.COMPOSITE or v.type_id == typeid.BITMASK or 
                v.type_id == typeid.BITMASK16 or v.type_id == typeid.BITMASK24 or
                v.type_id == typeid.BITMASK32 or v.type_id == typeid.BITMASK64 then
                local name = (v.abbr and (prefix..'.'..v.abbr)) or prefix
                parse_specification(protocol, name, v.sub_spec)
            else
                v.proto_field = create_protofield(prefix, v)
                table.insert(protocol.fields, v.proto_field)
            end
        end
    end

    local function is_number(id)
        return id == typeid.UINT8 or id == typeid.INT8 or 
        id == typeid.LE_UINT16 or id == typeid.BE_UINT16 or 
        id == typeid.LE_UINT24 or id == typeid.BE_UINT16 or 
        id == typeid.LE_UINT32 or id == typeid.BE_UINT32 or 
        id == typeid.LE_UINT64 or id == typeid.BE_UINT64 or 
        id == typeid.LE_INT16 or id == typeid.BE_INT16 or 
        id == typeid.LE_INT24 or id == typeid.BE_INT16 or 
        id == typeid.LE_INT32 or id == typeid.BE_INT32 or 
        id == typeid.LE_INT64 or id == typeid.BE_INT64
    end

    local function is_little_endian(id)
        return id == typeid.LE_UINT16 or id == typeid.LE_UINT24 or
        id == typeid.LE_UINT32 or id == typeid.LE_UINT64 or
        id == typeid.LE_INT16 or id == typeid.LE_INT24 or
        id == typeid.LE_INT32 or id == typeid.LE_INT64
    end

    local function get_type_size(id, size)
        if id == typeid.UINT8 or id == typeid.INT8 or id == typeid.CHAR or id == typeid.BOOL  or 
            id == typeid.BITMASK then
            return size or 1
        elseif id == typeid.BE_UINT16 or id == typeid.LE_UINT16 or id == typeid.BE_INT16 or 
            id == typeid.LE_INT16 or id == typeid.BITMASK16 then
            return size or 2
        elseif id == typeid.BE_UINT24 or id == typeid.LE_UINT24 or id == typeid.BE_INT24 or 
            id == typeid.LE_INT24 or id == typeid.BITMASK24 then
            return size or 3
        elseif id == typeid.BE_UINT32 or id == typeid.LE_UINT32 or id == typeid.BE_INT32 or 
            id == typeid.LE_INT32 or id == typeid.FLOAT or id == typeid.IPV4 or 
            id == typeid.BITMASK32 then
            return size or 4
        elseif id == typeid.ETHER then
            return size or 6
        elseif id == typeid.BE_UINT64 or id == typeid.LE_UINT64 or id == typeid.BE_INT64 or 
            id == typeid.LE_INT64 or id == typeid.DOUBLE or id == typeid.BITMASK64 then
            return size or 8
        elseif id == typeid.IPV6 or id == typeid.GUID then
            return size or 16
        elseif id == typeid.STRING or id == typeid.ABSOLUTE_TIME or id == typeid.RELATIVE_TIME or 
            id == typeid.STRINGZ or id == typeid.BYTES or id == typeid.UBYTES or 
            id == typeid.NONE or id == typeid.OID or id == typeid.PROTOCOL or
            id == typeid.REL_OID or id == typeid.SYSTEMID or id == typeid.EUI64 then
            assert(size, "Please check size values! All types without fixed length require the 'size' property.")
            return size
        else
            error("Please check type ids! The property 'type_id' contains undefined value.")
        end
    end

    function get_min_protocol_size(spec)
        local size = 0
        for k, v in pairs(spec) do
            local multiplier = 1
            size = (v.offset and v.offset > 0 and (size + v.offset)) or size
            if v.max_reps and type(v.max_reps) ~= 'string' then
                multiplier = v.max_reps
            end
            if v.type_id == typeid.COMPOSITE then
                size = size + multiplier * get_min_protocol_size(v.sub_spec)
            else
                local type_size = get_type_size(v.type_id, v.size)
                if type(type_size) ~= 'string' then
                    size = size + multiplier * type_size
                end
            end 
        end
        return size
    end

    local function add_size_to_map(map, buffer, key, id)
        if is_number(id) then
            if is_little_endian(id) then
                map[key] = buffer:le_uint64()
            else
                map[key] = buffer:uint64()
            end
        end
    end

    local function try_get_size(map, key)
        if type(key) == 'string' then
            return map[key]:tonumber()
        else
            return key
        end
    end

    local function generate_dissection_bitmask(protocol, root, spec, buffer, offset, size)
        for k, v in pairs(spec) do
            local reps = v.max_reps or 1
            for idx = 1,reps do
                if v.type_id == typeid.BITMASK or v.type_id == typeid.BITMASK16 or 
                        v.type_id == typeid.BITMASK24 or v.type_id == typeid.BITMASK32 or 
                        v.type_id == typeid.BITMASK64 then
                    local name = v.name
                    if v.name and 'function' == type(v.name) then
                        name = v.name(buffer(offset, size))
                    end
                    local tree = (name and root:add(protocol, buffer, name)) or root
                    generate_dissection_bitmask(protocol, tree, v.sub_spec, buffer, offset, size)
                else
                    local value_buffer = buffer(offset, size)
                    local mapped_value = nil
                    if v.mapping then
                        if type(v.mapping) == 'function' then
                            mapped_value = v.mapping(value_buffer)
                        elseif v.type_id == typeid.STRING or v.type_id == typeid.STRINGZ  then
                            mapped_value = v.mapping[value_buffer:string()]
                        end
                    end
                    if mapped_value then
                        root:add(v.proto_field, value_buffer, mapped_value)
                    else
                        root:add(v.proto_field, value_buffer)
                    end
                end
            end
        end
    end


    local function generate_dissection(protocol, root, spec, buffer, offset, size_map, skipped, start) 
        local size_map = size_map or {}
        local size, offset, key, skipped, start = 0, offset or 0, nil, skipped or nil, start or nil
        for k, v in pairs(spec) do
            local reps = try_get_size(size_map, v.max_reps) or 1
            for idx = 1,reps do 
                if not skipped and v.offset then
                    start = size
                    skipped = (v.offset >= 0 and v.offset) or (v.offset < 0 and (buffer:len() + v.offset - size))
                    size = (v.offset >= 0 and (size + v.offset)) or (v.offset < 0 and (buffer:len() + v.offset))
                elseif skipped and v.offset then
                    error("You can not set offset multiple times!")
                end
                if v.type_id == typeid.BITMASK or v.type_id == typeid.BITMASK16 or 
                        v.type_id == typeid.BITMASK24 or v.type_id == typeid.BITMASK32 or 
                        v.type_id == typeid.BITMASK64 then
                    local name = v.name
                    if v.name and 'function' == type(v.name) then
                        name = v.name(buffer(offset+size, get_type_size(v.type_id, v.size)))
                    end
                    local tree = (name and root:add(protocol, buffer, name)) or root

                    generate_dissection_bitmask(protocol, tree, v.sub_spec, buffer, offset+size, get_type_size(v.type_id, v.size))

                    size = size + get_type_size(v.type_id, v.size)
                elseif v.type_id == typeid.COMPOSITE then
                    local name = v.name
                    if v.name and 'function' == type(v.name) then
                        name = v.name(buffer(offset+size, get_min_protocol_size(v.sub_spec)))
                    end
                    local tree = (name and root:add(protocol, buffer, name)) or root
                    local sub_size, sub_start, sub_skipped, sub_key = generate_dissection(protocol, tree, v.sub_spec, buffer, offset+size, size_map, skipped, start)
                    key, size, start, skipped = key or sub_key, size + sub_size, start or sub_start, skipped or sub_skipped
                else
                    local type_size = try_get_size(size_map, get_type_size(v.type_id, v.size))
                    local value_buffer = buffer(offset+size, type_size)
                    key = (v.is_key and value_buffer) or key
                    add_size_to_map(size_map, value_buffer, v.abbr, v.type_id)
                    local mapped_value = nil
                    if v.mapping then
                        if type(v.mapping) == 'function' then
                            mapped_value = v.mapping(value_buffer)
                        elseif v.type_id == typeid.STRING or v.type_id == typeid.STRINGZ  then
                            mapped_value = v.mapping[value_buffer:string()]
                        end
                    end
                    if is_little_endian(v.type_id) then
                        if mapped_value then
                            root:add_le(v.proto_field, value_buffer, mapped_value)
                        else
                            root:add_le(v.proto_field, value_buffer)
                        end
                    else
                        if mapped_value then
                            root:add(v.proto_field, value_buffer, mapped_value)
                        else
                            root:add(v.proto_field, value_buffer)
                        end
                    end
                    size = size + type_size
                end
            end
        end
        return size, start, skipped, key
    end


    -- Create dissector from config
    function generate_dissector(config)
        assert(config.name, "Protocol name is missing!")
        assert(config.description, "Description property is missing!")

        if config.pre_init then
            config.pre_init(config)
        end

        local protocol = Proto(config.name, config.description)
        protocol.fields = {}

        local protocol_table = nil
        if config.key then
            protocol_table = DissectorTable.new(config.name..'.'..config.key.name, nil, typeid_to_ftype(config.key.type_id))
        else
            protocol_table = DissectorTable.new(config.name, nil, ftypes.UINT32)
        end

        if config.port_filter then
            assert(config.port_filter.range, "Port range is not specified!")
            assert(config.port_filter.protocol, "Protocol is not specified!")
            assert(config.port_filter.description, "Port filter description is missing!")
            assert(config.port_filter.max_value, "Port filter max. value is missing!")

            protocol.prefs.ports = Pref.range(config.name:upper()..'-Ports', config.port_filter.range, config.port_filter.description, config.port_filter.max_value)

            function protocol.init()
                local table = DissectorTable.get(config.port_filter.protocol..'.port')
                table:add(protocol.prefs.ports, protocol)
            end
        end

        if config.pre_parse then
            config.pre_parse(config, protocol, protocol_table)
        end

        parse_specification(protocol, config.name, config.spec)

        if config.post_parse then
            config.post_parse(config, protocol, protocol_table)
        end

        local size = get_min_protocol_size(config.spec)
        protocol.dissector = function(buffer, pinfo, tree)
            if config.pre_dissection then
                if not config.pre_dissection(config, protocol, buffer, pinfo, tree, size) then
                    return
                end
            end
            if buffer:len() < size then
                return
            else
                if config.col_info then
                    pinfo.cols.info:set(config.col_info(buffer))
                end
                pinfo.cols.protocol = protocol.name
                local subtree = tree
                if not config.no_subtree then
                    local label = config.label
                    if type(config.label) == 'function' then
                        label = config.label(buffer)
                    end
                    subtree = tree:add(protocol, buffer(), label)
                end
                local offset, skipstart, skipsize, key = generate_dissection(protocol, subtree, config.spec, buffer)
                if (buffer:len() > offset) or (skipsize and buffer:len() > (offset - skipsize)) and config.key then
                    local sub_buf = nil
                    if skipstart and skipsize then
                        sub_buf = buffer:range(skipstart, skipsize):tvb()
                    else 
                        sub_buf = buffer:range(offset):tvb()
                    end
                    if config.pass_root then
                        subtree = tree
                    end
                    if key then
                        protocol_table:try(typeid_to_value(config.key.type_id, key), sub_buf, pinfo, subtree)
                    else
                        protocol_table:try(0, sub_buf, pinfo, subtree)
                    end
                end
            end
        end

        if config.after then
            local dependency_table = DissectorTable.get(config.after.name..'.'..config.after.key)
            if type(config.after.value) == 'table' then
                for k, v in pairs(config.after.value) do
                    dependency_table:add(v, protocol)
                end
            else
                dependency_table:add(config.after.value, protocol)
            end
        end

        return protocol, table
    end
end
