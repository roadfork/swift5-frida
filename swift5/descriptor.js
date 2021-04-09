import { api, apihelper } from './api';

var descriptor = {};
var offset_ptr_size = 4;

descriptor.Descriptor = function Descriptor(dptr) {
    var flags;
    try {
        flags = dptr.readU32();
    } catch (error) {
        //console.error(`[!] unable to get descriptor flags`)
        return
    }
    let kind = flags & 15;
    // https://github.com/apple/swift/blob/main/docs/ABI/TypeMetadata.rst#common-metadata-layout
    switch (kind) {
        case 0:
            return {
                'kind': 'class', 'descriptor': {
                    'Flags': '0x' + flags.toString(16),
                    'Parent': dptr.add(dptr.add(1 * offset_ptr_size).readS32()), // calculated offset
                    'Name': dptr.add(2 * offset_ptr_size + dptr.add(2 * offset_ptr_size).readS32()).readUtf8String(), // calculated offset
                    'AccessFunction': dptr.add(3 * offset_ptr_size + dptr.add(3 * offset_ptr_size).readS32()), // calculated offset
                    'FieldDescriptor': dptr.add(4 * offset_ptr_size + dptr.add(4 * offset_ptr_size).readS32()), // calculated offset
                    'SuperclassType': dptr.add(5 * offset_ptr_size).readS32(),
                    'MetadataNegativeSizeInWords': dptr.add(6 * offset_ptr_size).readS32(),
                    'MetadataPositiveSizeInWords': dptr.add(7 * offset_ptr_size).readS32(),
                    'NumImmediateMembers': dptr.add(8 * offset_ptr_size).readS32(),
                    'NumFields': dptr.add(9 * offset_ptr_size).readS32(),
                    'FieldOffsetVectorOffset': dptr.add(10 * offset_ptr_size).readS32(),
                    'pointer': dptr
                }
            }
        case 1:
            return {
                'kind': 'struct', 'descriptor': {
                    'Flags': '0x' + flags.toString(16),
                    'Parent': dptr.add(dptr.add(1 * offset_ptr_size).readS32()), // calculated offset
                    'Name': dptr.add(2 * offset_ptr_size + dptr.add(2 * offset_ptr_size).readS32()).readUtf8String(), // calculated offset
                    'AccessFunction': dptr.add(3 * offset_ptr_size + dptr.add(3 * offset_ptr_size).readS32()), // calculated offset
                    'FieldDescriptor': dptr.add(4 * offset_ptr_size + dptr.add(4 * offset_ptr_size).readS32()), // calculated offset
                    'NumFields': dptr.add(5 * offset_ptr_size).readS32(),
                    'FieldOffsetVectorOffset': dptr.add(6 * offset_ptr_size).readS32(),
                    'pointer': dptr
                }
            }
        case 2:
            return {
                'kind': 'enum', 'descriptor': {
                    'Flags': '0x' + flags.toString(16),
                    'Parent': dptr.add(dptr.add(1 * offset_ptr_size).readS32()), // calculated offset
                    'Name': dptr.add(2 * offset_ptr_size + dptr.add(2 * offset_ptr_size).readS32()).readUtf8String(), // calculated offset
                    'AccessFunction': dptr.add(3 * offset_ptr_size + dptr.add(3 * offset_ptr_size).readS32()), // calculated offset
                    'FieldDescriptor': dptr.add(4 * offset_ptr_size + dptr.add(4 * offset_ptr_size).readS32()), // calculated offset
                    'NumPayloadCasesAndPayloadSizeOffset': dptr.add(5 * offset_ptr_size).readS32(),
                    'NumEmptyCases': dptr.add(6 * offset_ptr_size).readS32(),
                    'FieldOffsetVectorOffset': dptr.add(7 * offset_ptr_size).readS32(),
                    'pointer': dptr
                }
            }
        default:
            // can be noisy
            //console.warn(`[!] descriptor kind of ${kind} not implemented`);
            return null
    }

}

descriptor.getMethodInfo = function getMethodInfo(numberOfMethodDescriptors, dptr) {
    // Expects the start address of the descriptor (dptr) to calculate
    // the offset of the MethodDescriptor[VTableSize] array
    let mptr = dptr.add(11 * offset_ptr_size);
    var methods = new Array();
    let method_masks = { 'instance': 0x10, 'dynamic': 0x20 };
    let method_kinds = { 0: 'method', 1: 'init', 2: 'getter', 3: 'setter', 4: 'modifycoroutine', 5: 'readcoroutine' };
    for (let i = 0; i < numberOfMethodDescriptors; i++) {
        var method_info = { 'mask': null, 'kind': null, 'impl': null }
        let methodd = {
            'Flags': mptr.add(i * 2 * offset_ptr_size).readU32(),
            'Impl': mptr.add((i * 2 * offset_ptr_size) + offset_ptr_size).readS32()
        }
        for (let [key, value] of Object.entries(method_masks)) {
            if ((value & methodd['Flags']) == value) {
                method_info['mask'] = key;
            }
        }
        let kind = (methodd['Flags'] & 0xf);
        method_info['kind'] = method_kinds[kind];
        //TODO: figure this out and fix this next line. In production builds, the compiler
        // optimizes things and will sanitize the impl address if the method address can be
        // hardcoded or in-lined. But sometimes we still see a small value which is not a valid offset
        // as far as I can tell - but I don' know what it is yet.
        if (methodd['Impl'] < -10 || methodd['Impl'] > 10) {
            method_info['impl'] = mptr.add(i * 2 * offset_ptr_size).add(offset_ptr_size + methodd['Impl']);
        } else {
            method_info['impl'] = methodd['Impl'];
        }
        //method_info['mthd_descriptor_adr'] = mptr.add(i * 2 * offset_ptr_size);
        methods.push(method_info);
    }
    return methods;
}

descriptor.getFieldInfo = function getFieldInfo(fptr) {
    // Expects the start address (fptr) of the field descriptor
    var fields = new Array();
    // field descriptor
    let fieldd = {
        'MangledTypeName': fptr.readS32(),
        'Superclass': fptr.add(1 * offset_ptr_size).readS32(),
        'Kind': fptr.add(2 * offset_ptr_size).readS16(), // these are int16's
        'FieldRecordSize': fptr.add(2 * offset_ptr_size).add(2).readS16(), //these are int16's
        'NumFields': fptr.add(3 * offset_ptr_size).readS32()
    }
    for (let i = 0; i < fieldd['NumFields']; i++) {
        // field record
        let fieldr_ptr = fptr.add(4 * offset_ptr_size).add(i * offset_ptr_size * 3);
        let fieldr = {
            'Flags': '0x' + fieldr_ptr.readU32().toString(16),
            'MangledTypeName': fieldr_ptr.add(1 * offset_ptr_size).add(fieldr_ptr.add(1 * offset_ptr_size).readS32()),
            'FieldName': fieldr_ptr.add(2 * offset_ptr_size).add(fieldr_ptr.add(2 * offset_ptr_size).readS32()).readUtf8String()
        }

        // https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst#symbolic-references
        let controlChar = fieldr['MangledTypeName'].readU8();
        if (0x1 <= controlChar && controlChar <= 0x17) { var length = 4; }
        else if (0x18 <= controlChar && controlChar <= 0x1f) { var length = 8; }
        else { var length = undefined }
        switch (length) {
            case 4:
                if (controlChar == 0x1) {
                    //{any-generic-type, protocol, opaque-type-decl-name} ::= '\x01' .{4}
                    //Reference points directly to context descriptor
                    let metadata_ptr = api.funcs.swift_getTypeByMangledNameInContext(fieldr['MangledTypeName'], length + 1, 0, 0);
                    // https://github.com/apple/swift/blob/22506f9bdb009c0c82410406d825c87c08af7f29/include/swift/ABI/MetadataValues.h#L59
                    // if kind is > 0x400, its a class instance (pointer)
                    if (metadata_ptr.readPointer() > 0x400) {
                        var dptr = metadata_ptr.add(Process.pointerSize * 8).readPointer();
                    } else {
                        var dptr = metadata_ptr.add(Process.pointerSize).readPointer();
                    }
                    let _type = this.Descriptor(dptr);
                    try {
                        var name = _type.descriptor.Name;
                    } catch (error) {
                        var name = fieldr['MangledTypeName'];
                    }
                    fields.push({ 'name': fieldr['FieldName'], 'type': name })
                }
                if (controlChar == 0x2) {
                    //{any-generic-type, protocol, opaque-type-decl-name} ::= '\x02' .{4}
                    //Reference points indirectly to context descriptor
                    let offset = fieldr['MangledTypeName'].add(1).readS32();
                    let indirect_ptr = fieldr['MangledTypeName'].add(1).add(offset);
                    let dptr = indirect_ptr.readPointer();
                    let _type = this.Descriptor(dptr);
                    try {
                        var name = _type.descriptor.Name;
                    } catch (error) {
                        var name = fieldr['MangledTypeName'];
                    }
                    fields.push({ 'name': fieldr['FieldName'], 'type': name })
                }
                break;
            case 8:
                // TODO: implement
                console.log('case 8');
                break
            default:
                // it should be a mangled typename string but we have to be aware that the string may
                // not be null terminated and adjacent to the next ref starting with a control char
                // or may have 0xff padding.
                let re = /[^ -~]+/;
                let mangledName = fieldr['MangledTypeName'].readCString();
                if (re.test(mangledName)) {
                    var typeName = mangledName.substring(0, mangledName.search(re));
                } else {
                    var typeName = mangledName;
                }
                let demangled = apihelper.demangle('$s' + typeName);
                if (demangled.includes('$')) {
                    // noisy
                    //console.error(`[!] Type for ${fieldr['FieldName']} did not demangle`);
                }
                //console.log(JSON.stringify({ 'name': fieldr['FieldName'], 'type': demangled }));
                fields.push({ 'name': fieldr['FieldName'], 'type': demangled });
                break;
        }
    }
    return fields
}

export { descriptor };
