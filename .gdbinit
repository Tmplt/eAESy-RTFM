target remote :2331

define reload
    !cargo build --examples
    monitor reset
    load
    continue
end

monitor speed 1000
monitor clrbp
monitor reset
monitor halt
monitor regs
monitor speed auto
monitor flash breakpoints 1
monitor semihosting enable
monitor semihosting IOClient 1
load
monitor clrbp
monitor reset
monitor halt
monitor regs

break main
break rust_begin_unwind
break HardFault
continue
