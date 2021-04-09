
Module.ensureInitialized('libswiftCore.dylib');
Module.ensureInitialized('libswiftFoundation.dylib');
var swiftCoreFuncs = Module.enumerateExports("libswiftCore.dylib")
var api = {};
api.funcs = {
    // Many of these are not actually used in the rest of the files
    // Builtin.RawPointer is compatiable with Frida's NativePointer()
    swift_demangle: { 'ret': 'pointer', 'args': ['pointer', 'size_t', 'pointer', 'pointer', 'int32'] },

    swift_allocObject: { 'ret': 'pointer', 'args': ['pointer', 'int32', 'int32'] },

    swift_unknownObjectRetain: { 'ret': 'pointer', 'args': ['pointer'] },

    swift_bridgeObjectRetain: { 'ret': 'pointer', 'args': ['pointer'] },

    swift_getObjectType: { 'ret': 'pointer', 'args': ['pointer'] },

    swift_getDynamicType: { 'ret': 'pointer', 'args': ['pointer', 'pointer', 'bool'] },

    swift_retain: { 'ret': 'pointer', 'args': ['pointer'] },

    swift_release: { 'ret': 'void', 'args': ['pointer'] },

    swift_deallocClassInstance: { 'ret': 'void', 'args': ['pointer', 'int32', 'int32'] },

    swift_getTypeByMangledNameInContext: { 'ret': 'pointer', 'args': ['pointer', 'int32', 'int32', 'int32'] },

    swift_lookUpClassMethod: { 'ret': 'pointer', 'args': ['pointer', 'pointer', 'pointer'] },

    //static Swift.MemoryLayout.size(ofValue: A) -> Swift.Int [ $ss12MemoryLayoutO4size7ofValueSix_tFZ ]
    $ss12MemoryLayoutO4size7ofValueSix_tFZ: { 'ret': 'int32', 'args': ['pointer'] },

    //Swift._StringObject.getSharedUTF8Start() -> Swift.UnsafePointer<Swift.UInt8>
    $ss13_StringObjectV18getSharedUTF8StartSPys5UInt8VGyF: { 'ret': 'pointer', 'args': [] },

    //Swift.String.init(cString: Swift.UnsafePointer<Swift.UInt8>) -> Swift.String [ $sSS7cStringSSSPys5UInt8VG_tcfC ]
    // used for creating strings
    $sSS7cStringSSSPys5UInt8VG_tcfC: { 'ret': ['pointer', 'pointer'], 'args': ['pointer'] },

    // Swift.String.utf8CString.getter : Swift.ContiguousArray<Swift.Int8> [ $sSS11utf8CStrings15ContiguousArrayVys4Int8VGvg ]
    // used for reading strings
    $sSS11utf8CStrings15ContiguousArrayVys4Int8VGvg: { 'ret': 'pointer', 'args': ['pointer', 'pointer'] },

    //Swift.UnsafeRawPointer.init(Builtin.RawPointer) -> Swift.UnsafeRawPointer [ $sSVySVBpcfC ]
    $sSVySVBpcfC: { 'ret': 'pointer', 'args': ['pointer'] },

    //Swift.UnsafeRawPointer._rawValue.getter : Builtin.RawPointer [ $sSV9_rawValueBpvg ]
    $sSV9_rawValueBpvg: { 'ret': 'pointer', 'args': [] },

    //Swift.UnsafePointer.init(Builtin.RawPointer) -> Swift.UnsafePointer<A> [ $sSPySPyxGBpcfC ]
    $sSPySPyxGBpcfC: { 'ret': 'pointer', 'args': ['pointer'] },

    //static Swift.UnsafeMutableRawPointer.allocate(byteCount: Swift.Int, alignment: Swift.Int) -> Swift.UnsafeMutableRawPointer [ $sSv8allocate9byteCount9alignmentSvSi_SitFZ ]
    $sSv8allocate9byteCount9alignmentSvSi_SitFZ: { 'ret': 'pointer', 'args': ['int32', 'int32'] },

    //Swift.Bool.init(Builtin.Int1) -> Swift.Bool [ $sSbySbBi1_cfC ]
    $sSbySbBi1_cfC: { 'ret': 'pointer', 'args': ['int32'] },

    //Swift.unsafeBitCast<A, B>(_: A, to: B.Type) -> B [ $ss13unsafeBitCast_2toq_x_q_mtr0_lF ]
    $ss13unsafeBitCast_2toq_x_q_mtr0_lF: { 'ret': 'pointer', 'args': ['pointer', 'pointer'] },

    //Swift.dump<A>(_: A, name: Swift.Optional<Swift.String>, indent: Swift.Int, maxDepth: Swift.Int, maxItems: Swift.Int) -> A $ss4dump_4name6indent8maxDepth0D5Itemsxx_SSSgS3itlF
    $ss4dump_4name6indent8maxDepth0D5Itemsxx_SSSgS3itlF: { 'ret': 'pointer', 'args': ['pointer', '...', 'pointer', 'int32', 'int32', 'int32'] },

    // Swift._StringObject.getSharedUTF8Start() -> Swift.UnsafePointer<Swift.UInt8> [ $ss13_StringObjectV18getSharedUTF8StartSPys5UInt8VGyF ]
    $ss13_StringObjectV18getSharedUTF8StartSPys5UInt8VGyF: { 'ret': 'pointer', 'args': [] },

    // Swift.Dictionary.init() -> Swift.Dictionary<A, B> [ $sS2Dyxq_GycfC ]
    $sS2Dyxq_GycfC: { 'ret': 'pointer', 'args': [] },
}

api.data = {
    //type metadata for Swift.AnyObject [ $syXlN ]
    $syXlN: undefined,

    //nominal type descriptor for Swift.String [ $sSSMn ]
    $sSSMn: undefined,

    //type metadata for Swift.String [ $sSSN ]
    $sSSN: undefined,
}

Object.keys(api.funcs).forEach(function (exportName) {
    if (api.funcs[exportName] === null) {
        console.warn('[api] Not implemented: ' + exportName);
        api.funcs[exportName] = () => { throw new Error('[api] Not implemented: ' + exportName) }
    }
    else {
        let swiftFunc = swiftCoreFuncs.find(coreFunc => coreFunc.name === exportName);
        if (swiftFunc == undefined) {
            console.error('[api] Not found: ' + exportName);
            api.funcs[exportName] = () => { throw new Error('[api] Not found: ' + exportName) }
        } else {
            api.funcs[exportName] = new NativeFunction(ptr(swiftFunc.address), api.funcs[exportName].ret, api.funcs[exportName].args);
        }
    }
})

Object.keys(api.data).forEach(function (exportName) {
    let swiftFunc = swiftCoreFuncs.find(coreFunc => coreFunc.name === exportName);
    if (swiftFunc == undefined) {
        console.error('[api] Not found: ' + exportName);
        api.data[exportName] = () => { throw new Error('[api] Not found: ' + exportName) }
    } else {
        api.data[exportName] = ptr(swiftFunc.address);
    }
})

// add some api helper functions
var apihelper = {};
apihelper.demangle = (mangled) => {
    var fName = Memory.allocUtf8String(mangled);
    var demangledName = api.funcs.swift_demangle(fName, mangled.length, ptr(0), ptr(0), 0);
    return (Memory.readUtf8String(demangledName));
}

apihelper.swiftstring = (unsafe_pointer) => {
    let result = api.funcs.$sSS7cStringSSSPys5UInt8VG_tcfC(unsafe_pointer);
    return { 'x0': ptr(result[0]), 'x1': result[1] }
}

apihelper.readswiftstring = (x0, x1) => {
    let result = api.funcs.$sSS11utf8CStrings15ContiguousArrayVys4Int8VGvg(x0, x1);
    // its a Swift Array[Int8] so add 0x20 for the actual bytes
    return result.add(0x20).readUtf8String();
}

apihelper.searchcorefuncs = (searchstring, demangle = true) => {
    if (demangle) {
        swiftCoreFuncs.forEach(f => {
            try {
                if (apihelper.demangle(f.name).includes(searchstring)) {
                    console.log(apihelper.demangle(f.name), '[ ' + f.name + ' ]');
                }
            } catch (error) {
                //console.error(`[!] ${error}`);
                return
            }
        })
    } else {
        swiftCoreFuncs.forEach(f => {
            try {
                if (f.name.includes(searchstring)) {
                    console.log(f.name);
                }
            } catch (error) {
                //console.error(`[!] ${error}`);
                return
            }
        })
    }
}

export { api, apihelper };
