# swift5-frida

A [Frida](https://frida.re) powered testing library designed to assist with security assesments of iOS applications written in Swift 5. This project is not considered complete and certainly has bugs. Only Arm64 devices are supported (ie: modern iPhones and no simulators).

Go to the [instructions](#Instructions) to skip all the verbiage and get started.

## Design Inspiration
This project started out of my desire to understand more about how the Swift runtime works and how objects are managed in memory.
While reading up on these topics, I came across [Runtime](https://github.com/wickwirew/Runtime) - which works at a level that is very useful for mobile application security assessments. The ability to inspect objects at runtime is something that I have come to take for granted with Objective-C since Apple has provided an [Objective-C runtime library/API](https://developer.apple.com/documentation/objectivec/objective-c_runtime). Unfortunately, no such API exists (yet) for Swift but something like Runtime would provide a good alternative.

After spending some time examining Swift 5 applications in Hopper and lldb, I wanted to see if I could implement some of the features of the Swift Runtime project using Frida - mainly object type inspection, field name and offset discovery, and instantiation.

As further discussed below, finding an actual method implementation or address in code to begin your intrumentation can be challenging and therefore **you will still need a decompiler** to examine the application binaries in order to confirm and further discover where you need to do what. This library will only _assist_ with that.

### Honorable mentions
Some other blogs, projects and writeups that were all very helpful while working on this project:

- [swift-frida](https://github.com/maltek/swift-frida)
- [dsdump](https://derekselander.github.io/dsdump/)
- [Swift5 metadata reversing](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [A custom Swift runtime blog series](https://belkadan.com/blog/tags/swift-runtime/)
- [Video on Swift memory layout](https://www.youtube.com/watch?v=ERYNyrfXjlg)

## Examples
### Type info
Probably the most common task will be manually examining any types of interest once they have been enumerated. We can begin enumerating with:
- `typeshelper.enumerateTypes()`

or a more passive approach with:
- `typeshelper.watchTypeAllocs()`

The various arguments supported by each functuon and the differences between them is explained in more detail further down and in the JSDoc's. Both will populate the global `types` object which you can then use in the rest of your script.

The following output shows the enumerated result of the [IOSSecuritySuite MachOParse class](https://github.com/securing/IOSSecuritySuite/blob/5014963254647c1d0adf2627fcae6cea3cd367ae/IOSSecuritySuite/IntegrityChecker.swift#L175) type from [this ipa](https://github.com/sushi2k/SwiftSecurity). Note that the fields array lists the `type` and `offset` for each field name and the methods array **_may_** contain an implementation address in addition to the kind flags:

```json
"MachOParse": {
    "descriptor": {
        "AccessFunction": "0x10245a80c",
        "FieldDescriptor": "0x102466ff0",
        "FieldOffsetVectorOffset": 10,
        "Flags": "0x80000050",
        "MetadataNegativeSizeInWords": 2,
        "MetadataPositiveSizeInWords": 26,
        "Name": "MachOParse",
        "NumFields": 2,
        "NumImmediateMembers": 16,
        "Parent": "0x1024651e4",
        "SuperclassType": 0,
        "pointer": "0x1024651fc"
    },
    "fields": [
        {
            "name": "base",
            "offset": 16,
            "type": "Swift.UnsafePointer empty-list "
        },
        {
            "name": "slide",
            "offset": 24,
            "type": "Swift.Optional<Swift.Int>"
        }
    ],
    "kind": "class",
    "metadata": {
        "classAddressPoint": 16,
        "classFlags": 2,
        "classSize": 224,
        "iVarDestroyer": "0x0",
        "instanceAddressPoint": 0,
        "instanceAlignmentMask": 7,
        "instanceSize": 33,
        "kind": "0x10246a3f0",
        "objCRuntimeReserve1": "0x19fde0490",
        "objCRuntimeReserve2": "0x803000000000",
        "pointer": "0x10246a428",
        "rodataPointer": "0x2804f10a2",
        "superClass": "0x1e43d3ed8",
        "typeDescriptor": "0x1024651fc"
    },
    "methods": [
        {
            "impl": "0x10246523a",
            "mask": null
        },
        {
            "impl": 0,
            "kind": "getter",
            "mask": "instance"
        },
        // <<SNIP>> 
        {
            "impl": 0,
            "kind": "method",
            "mask": "instance"
        },
        {
            "impl": "0x10245a05c",
            "kind": "method",
            "mask": "instance"
        },
        {
            "impl": 0,
            "kind": "method",
            "mask": "instance"
        },
        {
            "impl": "0x10245a1ac",
            "kind": "method",
            "mask": "instance"
        }
    ],
    "module": "IOSSecuritySuite",
    "num_fields": 2,
    "num_methods": 14
},

```
### Object instantiation and modification
The following code shows how a new [Alamofire ServerTrustManager](https://alamofire.github.io/Alamofire/Classes/ServerTrustManager.html) can be allocated and used to replace the exsisting one normally created by the application:
``` javascript
import { Swift5 } from './swift5/importer';

Swift5.typeshelper.enumerateTypes();

// Session_init
Interceptor.attach(Swift5.types.Session.methods[10].impl, {
    onEnter(args) {
        var newServerTrustManager = Swift5.typeshelper.allocObject(Swift5.types.ServerTrustManager);
        var serverTrustManagerLayout = Swift5.typeshelper.getTypeLayout(
            Swift5.types.ServerTrustManager,
            newServerTrustManager
        );
        var emptyDictionary = new Swift5.basictype("Swift.Dictionary");
        emptyDictionary.init();
        serverTrustManagerLayout.allHostsMustBeEvaluated.writeU8(0);
        serverTrustManagerLayout.evaluators.writePointer(emptyDictionary.ptr);
        args[7] = newServerTrustManager;
        console.log(`[+] The session ServerTrustManager has been replaced with our own`);
    }
})
```
Here is a more detailed explanantion of each part of the script:

- `import { Swift5 } from './swift5/importer'`
    
    This import is all that is required to make the Swift5 testing library available to your script as well as the repl.

- `typeshelper.enumerateTypes()`

    As mentioned above, usually you will want to populate the types object with Swift 5 types being used by the instrumented application. This can be accomplished using either `enumerateTypes()` or `watchTypeAllocs()`. The former will attempt to actively enumerate Swift types available in modules that you specify whereas the latter will attach to `swift_allocObject()` and wait for the metadata pointer to be passed. 

- `types.Session.methods[10].impl`

    Now that some types have been enumerated, if we are lucky, some of the implementation addresses may be available in the type method descriptors. In this case, the init() method for the Session type was available and presents a good opportunity for runtime hooking since the reference to the ServerTrustManager is [passed on initialization](https://alamofire.github.io/Alamofire/Classes/Session.html#/s:9Alamofire7SessionC7session8delegate9rootQueue24startRequestsImmediately07requestF0013serializationF011interceptor18serverTrustManager15redirectHandler014cachedResponseQ013eventMonitorsACSo12NSURLSessionC_AA0B8DelegateCSo17OS_dispatch_queueCSbATSgAuA18RequestInterceptor_pSgAA06ServernO0CSgAA08RedirectQ0_pSgAA06CachedsQ0_pSgSayAA12EventMonitor_pGtcfc).
  
    As shown in the example earlier, each type known to the framework will usually have a large amount of associated information available including descriptor, metadata, fields and methods (if applicable) as well as field offsets and field types.

- `typeshelper.allocObject(Swift5.types.ServerTrustManager)`

    We now allocate a new object of type ServerTrustManager on the heap. Instance size and alignment mask is managed automatically during the allocation however it is up to you to ensure proper field alignment and type. These details can be obtained by looking at the type's `fields` property. See `getTypeLayout()` below for a helper method to assist with this.

- `typeshelper.getTypeLayout()`

    This function returns a new object with fieldname:address mappings starting from the offset provided when called, in this case the address of our new ServerTrustManager. We can use the returned layout to read and write field values of a matching object type at the correct address.

- `basictype("Swift.Dictionary")`

    A new empty Swift Dictionary is created and allocated on the heap. We can access the pointer for the dictionary from the objects `ptr` property.

- `serverTrustManagerLayout.allHostsMustBeEvaluated.writeU8(0)` and `serverTrustManagerLayout.evaluators.writePointer(emptyDictionary.ptr)`

    Use the layout object to write new values into our newly allocated ServerTrustManager. In this case we are assigning false to the `allHostsMustBeEvaluated` field and providing a pointer to an empty dictionary of evaluators to the `evaluators` field. This ServerTrustManager will therefore not be able to evaluate pinning for any host.

- `args[7] = newServerTrustManager`

    Finally use Frida's Interceptor to overwrite register x7 which contains the address of the actual (old) ServerTrustManager when Session is being initialized. The Session object will now use our new one.

### Swift Strings
Searching on the internet for "Frida Swift String" shows that some people have had a hard time reading or writing these, which is understandable. Swift Strings are made of two values: the count+flag bits and the bridge object. Depending on the size of the string, the count+flags value may be the string value itself. It is all explained in full detail [here](https://github.com/apple/swift/blob/main/stdlib/public/core/StringObject.swift) but I think [this documentation](https://github.com/TannerJin/Swift-MemoryLayout/blob/master/SwiftCore/String.swift) is much more helpful.

I initially started coding my own parser function similar to the approach [shown here](https://github.com/neil-wu/FridaHookSwiftAlamofire/blob/master/frida-agent/agent/SDSwiftString.ts), but then I wondered if the Swift runtime could help, and it turns out it can. For reading and writing Swift strings, I use the two following core methods:
- `Swift.String.init(cString: Swift.UnsafePointer<Swift.UInt8>) -> Swift.String`
- `Swift.String.utf8CString.getter : Swift.ContiguousArray<Swift.Int8>`

These functions are available in the swiftCore dylib and can be called as native functions with Frida. The library has a helper function to make reading strings a bit easier:
``` javascript
Swift5.apihelper.readswiftstring(args[0], args[1]);
```
and a basictype class to create new ones:
``` javascript
var newname = new Swift5.basictype("Swift.String");
newname.init(Memory.allocUtf8String("Some really long name over 15 chars as a test"));
// a few lines of code later...
driver.name.writePointer(newname.x0);
driver.name.add(Process.pointerSize).writePointer(newname.x1);
``` 
I am not sure if this strategy will result in unforseen problems but so far I have not encountered any.
## Instructions
For those who are familiar with Frida but have not used [frida-compile](https://github.com/frida/frida-compile), this project first requires that you download the required node packages and then compile your main JS script, which imports the required code from this library.

It is highly recommended to use an IDE such as MSCode which supports \[tab\] auto-complete and will display any associated JSDoc documentation.

1. Clone this repo:
```
git clone https://github.com/roadfork/swift5-frida.git
```
2. Navigate into the directory and install the required packages:
```
npm install
```
3. Create your script. A minimal example to get started would be:
``` javascript
import { Swift5 } from './swift5/importer';
Swift5.typeshelper.enumerateTypes();
```
4. Compile and then use Frida to load the compiled script:
```
./node_modules/.bin/frida-compile -o example_compiled.js -w example.js
```

### Function summary
A summary of most of the functions that you would use is provided below. Specifics pertaining to argument types and return values is contained in the JSDoc's.
- `apihelper`:
    - `demangle`: Demangle Swift function and type names.
    - `readswiftstring`: Read and print a Swift string.
    - `searchcorefuncs`: Search the Swift coreLib for something that may help with something you are trying to do. Will search mangled and demangled symbols.
- `basictype`: TODO
- `types`: Object that becomes populated with types observed or enumerated at runtime.
- `typeshelper`:
    - `allocObject`: Create an instance from a class type.
    - `enumerateTypes`: Attempts to enumerate all Swift types from the specified binary `__swift5_types` section. After identifying all descriptors this function will then call or intercept the AccessorFunction for each type to obtain the metadata pointer. Currently `classes`, `structs` and `enums` are supported.
    - `getTypeLayout`: A function to help generate a field layout mapping when writing to objects in memory.
    - `setMetaData`: A simple helper function to try and obtain the metadata pointer for classes and structs if not already enumerated. Metadata is required to know the field offsets in both these type kinds.
    - `showEnumeratedFields`: Show the values of all enumerated fields along with each associated field type.
    - `showEnumeratedTypes`: Show the type name and associated kind of all discovered types.
    - `watchAccessorFunctions`: Prints a backtrace when the AccessorFunction for each enumerated type is called. May be useful for tracking types especially from Frameworks.
    - `watchTypeAllocs`: Types helper function to monitor all or specified types being allocated and deallocated. Allocated types will be enumerated for other information (descriptor, metatdata etc..) and added to the global `types` object. Type instances are added to the global `instances` object.
- `instances`: A global object to track alloc'd objects.
- `instanceshelper`:
    - `startStalking`: A helper function to set up and start the `Stalker` to try and help identify areas of code and function calls which pertain to a particular object or object type. This is done by monitoring any branch with link (bl) instructions that are made where the x0 or x20 registers point to the object instance or the type for that instance. Should this condition be met, the instruction address and a backtrace is printed to the console. This Stalker instance can be stopped by calling `instanceshelper.stopStalking()`. A typical implementation would be to use this function with `typeshelper.watchTypeAllocs()`.

## Production versus Development Builds

An important design goal of this project was to be able to provide as much detail as possible when dealing with iOS production builds.

There are a few problematic changes that we encounter with production builds which are detailed below. If testing any of your own iOS apps, I recommend first archiving the build and sideloading the built product within the archive, since this will most closely resemble a production build.

### Stripping
Symbols in the main binary will be stripped. This means there is limited information for a decompiler to use when trying to cross-reference a method (function) name.

### Sanitizing
In addition to removing symbol names, the compiler may further sanitize the binary including the implementation address pointer normally contained in the method descriptors if the method becomes inlined or statically dispatched. You will frequently observe this on production builds where the implementation address is null'd. In the case of a null implementation address, we can still obtain a list of class and instance methods along with some [flags describing the purpose of the method](https://derekselander.github.io/dsdump/#swift_methods_in_a_class), but we cannot easily resolve where the function logic is.

To assist with this problem, this library has an `instanceshelper.startStalking()` convenience function to initialize Frida's [Stalker](https://frida.re/docs/stalker/) to watch for any `bl` instructions where either the specified object or object type is in the x0 or x20 register. In the [Swift Arm64 calling convention](https://github.com/apple/swift/blob/main/docs/ABI/RegisterUsage.md), x0 will contain the first argument to a new procedure while x20 is the context register. In addition to printing a backtrace, the address of the `bl` instruction is printed, which can then be further investigated in your decompiler. This strategy has shown to be relatively effective in helping to discover type related method code that has been in-lined or optimized in some way. 

### Single binary
I have noticed that when building iOS applications that use [Swift package dependencies](https://developer.apple.com/documentation/xcode/adding_package_dependencies_to_your_app), the compiled product usually only consisists of a single binary. The compiler does not build the package dependency as a Framework that is then included in the ipa, but rather the code is compiled and linked into one single binary. Combined with the stripping and sanitizing steps made during a production build, this can make discovery of these additional packages challenging as well. Should the application include a Frameworks folder, these libraries usally contain much more information since the compiler cannot optimize in the same way (exports cannot be stripped and the methods may have to be dynamically dispatched at runtime).
