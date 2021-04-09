var instances = {};

var instanceshelper = {};
var tid;
var stalkerRunning = false;
/**
 * A helper function to set up and start the `Stalker` to try and help identify areas of code and function
 * calls which pertain to a particular object or object type. This is done by monitoring any branch with
 * link (bl) instructions that are made where the x0 or x20 registers point to the object instance or the
 * type for that instance. Should this condition be met, the instrruction address and a backtrace is printed
 * to the console.
 * This Stalker instance can be stopped by calling `instanceshelper.stopStalking()`.
 * A typical implementation would be to use this function with `typeshelper.watchTypeAllocs()`:
 * @param {NativePointer} instanceAddress - The address of the instance to monitor.
 * @param {NativePointer} base - Base address of the application code to start monitoring at.
 * @param {number} size - The size of the application code to be monitoring starting from `base`.
 * @returns 
 * @example
 * Swift5.typeshelper.watchTypeAllocs(true, 'SomeClassType', {
 *  onAlloc(name, address) {
 *    if (name == 'SomeClassType') {
 *        Swift5.instanceshelper.startStalking(address, mainBinary.base, mainBinary.size);
 *     }
 *  },
 *   onDealloc(name) {
 *      if (name == 'SomeClassType') {
 *          Swift5.instanceshelper.stopStalking();
 *      }
 *  }
 * })
 */
instanceshelper.startStalking = (instanceAddress, base, size) => {
    if (stalkerRunning) {
        console.error(`[!] Stalker already tracking ${instanceAddress}. Call stopStalking() for manual stop.`)
        return
    }
    stalkerRunning = true;
    let programBase = base;
    let programEnd = programBase.add(size)
    tid = Process.getCurrentThreadId();
    let metadata_ptr = instanceAddress.readPointer();

    function checkRegisters(context) {
        // https://github.com/apple/swift/blob/main/docs/ABIStabilityManifesto.md#call-context-register
        // https://github.com/apple/swift/blob/main/docs/ABI/RegisterUsage.md
        if (context.x0.equals(instanceAddress)) {
            let offset = ptr(context.pc).sub(programBase);
            console.warn(`\n[?] Possible [object] related call @ ${context.pc} (offset: ${offset})\n  - x0: ${context.x0}`);
            //console.log('  - backtrace:\n' + Thread.backtrace(context).map(DebugSymbol.fromAddress).join('\n') + '\n');
        }
        if (context.x0.equals(metadata_ptr)) {
            let offset = ptr(context.pc).sub(programBase);
            console.warn(`\n[?] Possible [object type] related call @ ${context.pc} (offset: ${offset})\n  - x0(type): ${context.x0}`);
            //console.log('  - backtrace:\n' + Thread.backtrace(context).map(DebugSymbol.fromAddress).join('\n') + '\n');
        }
        if (context.x20.equals(instanceAddress)) {
            let offset = ptr(context.pc).sub(programBase);
            console.warn(`\n[?] Possible [instance method] related call @ ${context.pc} (offset: ${offset})\n  - x20: ${context.x20}`);
            //console.log('  - backtrace:\n' + Thread.backtrace(context).map(DebugSymbol.fromAddress).join('\n') + '\n');
        }
        if (context.x20.equals(metadata_ptr)) {
            let offset = ptr(context.pc).sub(programBase);
            console.warn(`\n[?] Possible [class/static method] related call @ ${context.pc} (offset: ${offset})\n  - x20(type): ${context.x20}`);
            //console.log('  - backtrace:\n' + Thread.backtrace(context).map(DebugSymbol.fromAddress).join('\n') + '\n');
        }
    }
    
    console.log(`[+] Starting Stalker`);
    Stalker.follow(tid, {
        events: {
            compile: true
        },
        transform(iterator) {
            let instruction = iterator.next();
            let withinProgCode = (instruction.address.compare(programBase) >= 0 &&
                instruction.address.compare(programEnd) === -1);
            do {
                if (withinProgCode && instruction.mnemonic === 'bl') {
                    iterator.putCallout(checkRegisters);
                }
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        }
    })
}

instanceshelper.stopStalking = () => {
    Stalker.unfollow(tid);
    Stalker.garbageCollect();
    console.log(`[+] Stalker stopped`)
    stalkerRunning = false;
}

export { instances, instanceshelper };
