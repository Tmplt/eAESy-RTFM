Whiteboard — a place for thoughts
---

LPC43s50 appears to be legacy, and the combination with the LPC4357 board seems a rare one; no specific documentation is offered.

AES API table is at at offset from the `BOOTROM_BASE`; see `example/lpc_chip_43xx/src/aes_18xx_43xx.c` —
if inconclusive or broken for this project's hardware, it can probably be used as base together with data sheet.
Topical code:
```c
#define BOOTROM_BASE			0x10400100
#define AES_API_TABLE_OFFSET	0x2

static unsigned long *BOOTROM_API_TABLE;

void Chip_AES_Init(void)
{
	uint32_t (*ROM_aes_Init)(void);

	BOOTROM_API_TABLE = *((unsigned long * *) BOOTROM_BASE + AES_API_TABLE_OFFSET);

	ROM_aes_Init		= (uint32_t (*)(void))BOOTROM_API_TABLE[0];
	aes_SetMode			= (uint32_t (*)(CHIP_AES_OP_MODE_T AesMode))BOOTROM_API_TABLE[1];
	aes_LoadKey1		= (void (*)(void))BOOTROM_API_TABLE[2];
	aes_LoadKey2		= (void (*)(void))BOOTROM_API_TABLE[3];
	aes_LoadKeyRNG		= (void (*)(void))BOOTROM_API_TABLE[4];
	aes_LoadKeySW		= (void (*)(uint8_t *pKey))BOOTROM_API_TABLE[5];
	aes_LoadIV_SW		= (void (*)(uint8_t *pVector))BOOTROM_API_TABLE[6];
	aes_LoadIV_IC		= (void (*)(void))BOOTROM_API_TABLE[7];
	aes_Operate			= (uint32_t (*)(uint8_t *pDatOut, uint8_t *pDatIn, uint32_t Size))BOOTROM_API_TABLE[8];
	aes_ProgramKey1		= (uint32_t (*)(uint8_t *pKey))BOOTROM_API_TABLE[9];
	aes_ProgramKey2		= (uint32_t (*)(uint8_t *pKey))BOOTROM_API_TABLE[10];
	aes_Config_DMA		= (uint32_t (*)(uint32_t channel_id))BOOTROM_API_TABLE[11];
	aes_Operate_DMA		= (uint32_t (*)(uint32_t channel_id, uint8_t *dataOutAddr, uint8_t *dataInAddr, uint32_t size))BOOTROM_API_TABLE[12];
	aes_Get_Status_DMA	= (uint32_t (*) (uint32_t channel_id))BOOTROM_API_TABLE[13];

	ROM_aes_Init();
}
```

