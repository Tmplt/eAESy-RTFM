/* S32K144EVB-Q100 memory.x */

MEMORY
{
  FLASH : ORIGIN = 0x0000000, LENGTH = 512K
  RAM : ORIGIN = 0x20000000, LENGTH = 16K
}

/* XXX: ? _stack_start should be something like ORIGIN(RAM) + LENGTH(RAM) */
/* but what about _stext? */
_stack_start = 0x1FFFFFFF;
_stext = 0x410;
