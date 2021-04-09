let meta = {};

function ClassMetaDataLayout(pointer) {
    /* example
    0000000100565e20                        dq         0x0000000100565de8           ; DATA XREF=Car type metadata accessor+4, 0x100560108
    0000000100565e28                        dq         0x000000010058c0a8           ; superclass
    0000000100565e30                        dq         0x000000010058c0d8
    0000000100565e38                        dq         0x0000000000000000
    0000000100565e40                        dq         0x00000001005641da           ; ro data ptr
    0000000100565e48                        dd         0x00000002                   ; flags
    0000000100565e4c                        dd         0x00000000                   ; instance address point
    0000000100565e50                        dd         0x00000048                   ; instance size
    0000000100565e54                        dd         0x00000007                   ; instance alignment mask
    0000000100565e58                        dd         0x000000d8                   ; class object size
    0000000100565e5c                        dd         0x00000010                   ; class object address point
    0000000100565e60                        dq         Class Car descriptor         ; nominal type descriptor
    0000000100565e68                        dq         0x0000000000000000           ; ivar destroyer
    */
    return {
        kind: pointer.readPointer(), // isaPointer for classes
        superClass: pointer.add(1*Process.pointerSize).readPointer(),
        objCRuntimeReserve1: pointer.add(2*Process.pointerSize).readPointer(),
        objCRuntimeReserve2: pointer.add(3*Process.pointerSize).readPointer(),
        rodataPointer: pointer.add(4*Process.pointerSize).readPointer(),
        classFlags: pointer.add(5*Process.pointerSize).readU32(),
        instanceAddressPoint: pointer.add(5*Process.pointerSize + 4).readU32(),
        instanceSize: pointer.add(6*Process.pointerSize).readU32(),
        instanceAlignmentMask: pointer.add(6*Process.pointerSize + 4).readU32(),
        classSize: pointer.add(7*Process.pointerSize).readU32(),
        classAddressPoint: pointer.add(7*Process.pointerSize + 4).readU32(),
        typeDescriptor: pointer.add(8*Process.pointerSize).readPointer(),
        iVarDestroyer: pointer.add(9*Process.pointerSize).readPointer(),
    }
}

function StructMetaDataLayout(pointer) {
    return {
        kind: pointer.readPointer(), // value of 0x200 for structs
        typeDescriptor: pointer.add(Process.pointerSize).readPointer()
    }
}

function EnumMetaDataLayout(pointer) {
    return {
        kind: pointer.readPointer(), // value of ... for enums
        typeDescriptor: pointer.add(Process.pointerSize).readPointer()
    }
}

meta.Layout = function Layout(kind, pointer) {
    switch (kind) {
        case 'class':
            return ClassMetaDataLayout(pointer)
        case 'struct':
            return StructMetaDataLayout(pointer)
        case 'enum':
            return EnumMetaDataLayout(pointer)
        default:
            console.warn(`[!] Metatdata layout for kind ${kind} not implemented`);
            break;
    }
}

export { meta };
