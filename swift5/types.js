import { api, apihelper } from './api';
import { meta } from './meta';
import { descriptor } from './descriptor';
import { instances } from './instances';

Module.ensureInitialized('libmacho.dylib');
var getsectiondata_ptr = Module.findExportByName('libmacho.dylib', 'getsectiondata');
var getsectiondata = new NativeFunction(getsectiondata_ptr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

var segment = Memory.allocUtf8String('__TEXT');
var section = Memory.allocUtf8String('__swift5_types');
var size_alloc = Memory.alloc(8);
var offset_ptr_size = 4;
var types = {};

/**
 * Attempts to enumerate all Swift types from the binary `__swift5_types` section. After identifying all descriptors 
 * this function will then call or intercept the AccessorFunction for each type to obtain the metadata pointer.
 * Currently `classes`, `structs` and `enums` are supported.
 * Direct AccessorFunction calls may cause problems on large apps early in the start process in which case you can try
 * to call this fuction at a later time.
 * @param {Boolean} direct - Call AccessorFunction directly for each type. Defaults to false in which case an `Interceptor`
 * is used.
 * @param {[Module]} modules - Optional array of modules (ie: `Process.enumerateModules()`) to enumerate Swift5 types from.
 * Defaults to the main binary if no modules are provided.

 */
function enumerateTypes(direct = false, modules = null) {
    if (modules == null) {
        modules = [Process.enumerateModules()[0]];
    }
    modules.forEach((binary) => {
        var swift5_types_ptr = getsectiondata(binary.base, segment, section, size_alloc);
        if (swift5_types_ptr.isNull()) {
            console.error(`[!] swift5_types section not found for ${binary.name}`);
            return
        };
        console.log(`\n[+] Enumerating types from ${binary.name}`);
        var sectionSize = Memory.readULong(size_alloc);
        // create a type_references array from the __swift5_types section
        var type_references = new Array();
        for (let i = 0; i < sectionSize; i = i + offset_ptr_size) {
            var type_ref = new Object();
            type_ref['from'] = swift5_types_ptr.add(i);
            type_ref['to'] = type_ref['from'].add(type_ref['from'].readS32());
            type_references.push(type_ref);
        }
        type_references.forEach(type_ref => {
            let dptr = type_ref['to'];
            setTypeInfo(dptr, binary);
        })
    })
    /*
    TODO:
    Not crazy about these strategies for actively getting the metadata pointer.
    watchTypeAllocs() should also be able to reliably get it (see that function below).
    but of course the type must be alloc'd.
    We can also use try and use the ObjC runtime:
        ObjC.classes['module.Wallet']
        {
            "handle": "0x100eefe30" << metadata ptr
        }
    */
    if (direct) {
        Object.entries(types).forEach(([name, thetype]) => {
            try {
                let accessorFunc = new NativeFunction(thetype.descriptor.AccessFunction, 'pointer', []);
                let pointer = accessorFunc();
                thetype['metadata'] = meta.Layout(thetype.kind, pointer);
                // track this as well for later
                thetype.metadata['pointer'] = pointer;
                // once we know the metadata pointer, determine field offsets
                setFieldOffsets(thetype);
            } catch (error) {
                console.error(`[!] Could not call AccessorFunction for type ${name}:\n${error}`);
            }
        })
    } else {
        Object.entries(types).forEach(([name, thetype]) => {
            Interceptor.attach(thetype.descriptor.AccessFunction, {
                onLeave(retval) {
                    try {
                        let pointer = ptr(retval);
                        thetype['metadata'] = meta.Layout(thetype.kind, pointer);
                        thetype.metadata['pointer'] = pointer;
                        setFieldOffsets(thetype);
                    } catch {
                        console.error(`[!] Could not intercept AccessorFunction for type ${name}:\n${error}`);
                    }
                }
            })
        })
    }
}

function setFieldOffsets(thetype) {
    if (thetype.kind == 'class') {
        for (let i = 0; i < thetype.descriptor.NumFields; i++) {
            thetype.fields[i].offset = thetype.metadata.pointer.add(
                thetype.descriptor.FieldOffsetVectorOffset * Process.pointerSize).add(
                    i * Process.pointerSize).readInt();
        }
    }
    if (thetype.kind == 'struct') {
        for (let i = 0; i < thetype.descriptor.NumFields; i++) {
            thetype.fields[i].offset = thetype.metadata.pointer.add(
                Process.pointerSize * 2).add(i * offset_ptr_size).readU32();
        }
    }
}

function setTypeInfo(dptr, binary) {
    let type = descriptor.Descriptor(dptr);
    if (type == undefined) return;
    switch (type.kind) {
        case 'class':
            // class methods
            let num_methods = type.descriptor['NumImmediateMembers'] - type.descriptor['NumFields'];
            try {
                var fieldInfo = descriptor.getFieldInfo(type.descriptor['FieldDescriptor']);
            } catch (error) {
                // we sometimes get access-violation errors. save it here to look at later 
                var fieldInfo = [error];
            }
            var info = {
                'kind': type.kind,
                'num_fields': type.descriptor['NumFields'],
                'fields': fieldInfo,
                'num_methods': num_methods,
                'methods': descriptor.getMethodInfo(num_methods, dptr),
                'descriptor': type.descriptor,
                'module': binary.name
            };
            types[type.descriptor.Name] = info;
            return types[type.descriptor.Name]
        //break;
        case 'struct':
            try {
                var fieldInfo = descriptor.getFieldInfo(type.descriptor['FieldDescriptor']);
            } catch (error) {
                var fieldInfo = [error];
            }
            var info = {
                'kind': type.kind,
                'num_fields': type.descriptor['NumFields'],
                'fields': fieldInfo,
                'descriptor': type.descriptor,
                'module': binary.name
            };
            types[type.descriptor.Name] = info;
            return types[type.descriptor.Name]
        //break;
        case 'enum':
            try {
                var fieldInfo = descriptor.getFieldInfo(type.descriptor['FieldDescriptor']);
            } catch (error) {
                var fieldInfo = [error];
            }
            var info = {
                'kind': type.kind,
                'num_fields': type.descriptor['NumFields'],
                'fields': fieldInfo,
                'descriptor': type.descriptor,
                'module': binary.name
            };
            types[type.descriptor.Name] = info;
            return types[type.descriptor.Name]
        //break;
        default:
            console.warn('[!] Type kind not implmented');
            break;
    }
}

class basictype {
    constructor(type) {
        this.type = type;
        switch (this.type.toString()) {
            case 'Swift.String':
                this.init = (address) => {
                    let retval = apihelper.swiftstring(address);
                    this.x0 = retval['x0'];
                    this.x1 = retval['x1'];
                }
                break;
            case 'Swift.Dictionary':
                // returns a pointer to an empty dictionary
                this.init = () => { this.ptr = api.funcs.$sS2Dyxq_GycfC() }
                break;
            // the remaining are not really necessary but have been included for reference
            case 'Swift.UnsafeRawPointer':
                this.init = (pointer) => { this.val = pointer };
                break;
            case 'Swift.Bool':
                this.init = (val) => {
                    this.ptr = Memory.alloc(8);
                    this.ptr.writeU8(val);
                    this.val = this.ptr.readU8();
                }
                break;
            case 'Swift.Int':
                this.init = (val) => {
                    this.ptr = Memory.alloc(8);
                    this.ptr.writeInt(val);
                    this.val = this.ptr.readInt()
                }
            default:
                console.warn('[!] Basic type not implemented')
                break;
        }
    }
}

/**
 * Show the enumerated type name and associated kind of all types.
 * @param {string} modulename - Optional case sensitive module name to match types against.
 */
function showEnumeratedTypes(modulename) {
    Object.entries(types).forEach(([name, thetype]) => {
        if (modulename != undefined) {
            if (thetype.module.includes(modulename)) {
                console.log(`${thetype.kind} ${name}`);
            }
        } else {
            console.log(`${thetype.kind} ${name}`);
        }
    })
}

/**
 * Show the values of all enumerated fields along with each associated field type.
 * @param {string} searchstring - Optional case senstive value to search for within each field
 * and print only those matching.
 */
function showEnumeratedFields(searchstring) {
    Object.entries(types).forEach(([name, thetype]) => {
        var output = '';
        var show = false;
        thetype.fields.forEach((field) => {
            if (searchstring != undefined) {
                if (field.name.includes(searchstring)) {
                    output += `  - ${field.name}: ${field.type}\n`;
                    show = true
                }
            } else {
                output += `  - ${field.name}: ${field.type}\n`;
                show = true;
            }
        })
        if (show) console.log(`\nFields for type ${name}:\n` + output);
        show = false;
    })
}

/**
 * Types helper function to monitor all or specified types being allocated and deallocated.
 * Allocated types will be enumerated for other information (descriptor, metatdat etc..) and
 * added to the global `types` object. Type instances are added to the global `instances` object.
 * @param {Boolean} print - Whether or not to print alloc/dealloc's. Defaults to false.
 * @param {[String]} typenames - Optional string or array of strings for specific types to watch.
 * Defaults to `null` in which case all types are watched. If using the default then the `callback`
 * will not be called even if provided.
 * @param {{onAlloc?: (name, address) => {}, onDealloc?: (name) => {}}} callback - Optional callback
 * that is called on alloc/dealloc's. The type name (and object address for alloc's) is passed to the
 * callback. The callback logic will need to be able to handle the type name if multiple types are being
 *  watched. `typenames` must be provided for the callback to be used.
 * @example
 * Swift5.typeshelper.watchTypeAllocs(true, 'SomeClassType', {
 *   onAlloc(name, address) {
 *       if (name == 'SomeClassType') {
 *           // alloc handling code here
 *       }
 *   },
 *   onDealloc(name) {
 *       if (name == 'SomeClassType') {
 *           // dealloc handling code here
 *      }
 *  }
 * })
 */
function watchTypeAllocs(print = false, typenames = null, callback = null) {
    Interceptor.attach(api.funcs.swift_allocObject, {
        onEnter(args) {
            this.metadata_ptr = args[0];
            if (this.metadata_ptr.readPointer() > 0x400) {
                this.dptr = this.metadata_ptr.add(Process.pointerSize * 8).readPointer();
            } else {
                this.dptr = this.metadata_ptr.add(Process.pointerSize).readPointer();
            }
        },
        onLeave(retval) {
            let instance_ptr = ptr(retval) // deep copy
            let type = setTypeInfo(this.dptr, { 'name': 'discovered during allocObject()' })
            if (type == undefined) return;
            type['metadata'] = meta.Layout(type.kind, this.metadata_ptr);
            type.metadata['pointer'] = this.metadata_ptr;
            try {
                setFieldOffsets(type);
            } catch (error) {
                // this seems to happen for certain built-ins where there was a memory
                // access issue during enumeration of the fields. dump the 'type' which
                // will contain more details: JSON.stringify(type, null, 2)
                // noisy
                //console.error(`[!] ${error}`);
            }
            let name = type.descriptor.Name;
            if (typenames != null) {
                typenames = [].concat(typenames);
                typenames.forEach((typename) => {
                    if (typename == name) {
                        if (print) console.warn(`[+] ${name} alloc'd @ ${instance_ptr}`);
                        if (!(name in instances)) {
                            instances[name] = new Array();
                        }
                        instances[name].push(instance_ptr);
                        if (callback != null && 'onAlloc' in callback) {
                            callback.onAlloc(name, instance_ptr)
                        }
                    }
                })
            } else {
                // do all of them but only show ones not starting with _
                if (print && name.charAt(0) != '_') console.warn(`[+] ${name} alloc'd @ ${instance_ptr}`);
                if (!(name in instances)) {
                    instances[name] = new Array();
                }
                instances[name].push(instance_ptr);
            }
        }
    })
    Interceptor.attach(api.funcs.swift_deallocClassInstance, {
        onEnter(args) {
            Object.entries(instances).forEach(([name, inst_address_array]) => {
                inst_address_array.forEach((inst_address, index) => {
                    if (args[0].equals(inst_address)) {
                        if (print && name.charAt(0) != '_') console.warn(`[-] ${name} @ ${inst_address} dealloc'd`);
                        instances[name].splice(index, 1);
                        if (callback != null && 'onDealloc' in callback) {
                            callback.onDealloc(name)
                        }
                    }
                })
            })
        }
    })
}

/**
 * Prints a backtrace when the AccessorFunction for each enumerated type is called.
 * May be useful for tracking types especially from Frameworks and libraries.
 */
function watchAccessorFunctions() {
    Object.entries(types).forEach(([name, thetype]) => {
        Interceptor.attach(thetype.descriptor.AccessFunction, {
            onEnter(args) {
                console.log(`[-] Accessor for ${name}`);
                console.log('from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n') + '\n');
            }
        })
    })
}

/**
 * A simple helper function to try and obtain the metadata pointer for classes and structs
 * if not already enumerated. Metadata is required to know the field offsets in both these type kinds.
 * @param {type} type The `type` as obtained from `enumerateTypes()` or `watchTypeAllocs()`. 
 * @returns NativePointer to the metadata for the provided type. This function also updates the type object
 * including the field offsets.
 */
function setMetaData(type) {
    let accessorFunc = new NativeFunction(type.descriptor.AccessFunction, 'pointer', []);
    let pointer = accessorFunc();
    type['metadata'] = meta.Layout(type.kind, pointer);
    type.metadata['pointer'] = pointer;
    setFieldOffsets(type);
    return type.metadata['pointer'];
}

/**
 * A simple alloc helper for class objects. Note that the object is not retained or dealloc'd.
 * The function will attempt to directly call the class type's AccessorFunction if the
 * metadata is not known.
 * @param {type} type The `type` as obtained from `enumerateTypes()` or `watchTypeAllocs()`.
 * @returns NativePointer to the alloc'd object.
 */
function allocObject(type) {
    if (!(type.kind == 'class')) {
        console.error(`[!] Type is not a class`)
        return
    }
    // get the metadata pointer if we do not already have it
    if (!('metadata' in type)) {
        setMetaData(type);
    }
    let pointer = api.funcs.swift_allocObject(type.metadata.pointer, type.metadata.instanceSize,
        type.metadata.instanceAlignmentMask);
    console.log(`[-] alloc'd ${type.metadata.instanceSize} bytes @ ${pointer} for type ${type.descriptor.Name}`);
    return pointer;
}

/**
 * A function to help generate a field layout mapping when writing to objects in memory.
 * @param {type} type The `type` as obtained from `enumerateTypes()`.
 * @param {*} pointer NativePointer to the alloc'd object (or 0x0 if you want just the offsets). See `allocObject()`.
 * @returns An object with a name:pointer key/value for each field in the provided type.
 * The field pointer value will be at the appropriate offset for that object's memory
 * location and that field name.
 * @example
 * 
 {
    "driver": "0x283530670",
    "make": "0x283530688",
    "automatic": "0x283530698",
    "speed": "0x2835306a0",
    "vin": "0x2835306a8"
 }
 */
function getTypeLayout(type, pointer) {
    var layout = {};
    type.fields.forEach(field => {
        layout[field.name] = pointer.add(field.offset)
    });
    return layout
}

var typeshelper = {};
typeshelper.enumerateTypes = enumerateTypes;
typeshelper.showEnumeratedTypes = showEnumeratedTypes;
typeshelper.showEnumeratedFields = showEnumeratedFields;
typeshelper.watchTypeAllocs = watchTypeAllocs;
typeshelper.watchAccessorFunctions = watchAccessorFunctions;
typeshelper.allocObject = allocObject;
typeshelper.setMetaData = setMetaData;
typeshelper.getTypeLayout = getTypeLayout;

export { types, basictype, typeshelper };
