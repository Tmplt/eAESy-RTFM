/*
 * @brief AES example
 *
 * @note
 * Copyright(C) NXP Semiconductors, 2015
 * All rights reserved.
 *
 * @par
 * Software that is described herein is for illustrative purposes only
 * which provides customers with programming information regarding the
 * LPC products.  This software is supplied "AS IS" without any warranties of
 * any kind, and NXP Semiconductors and its licensor disclaim any and
 * all warranties, express or implied, including all implied warranties of
 * merchantability, fitness for a particular purpose and non-infringement of
 * intellectual property rights.  NXP Semiconductors assumes no responsibility
 * or liability for the use of the software, conveys no license or rights under any
 * patent, copyright, mask work right, or any other intellectual property rights in
 * or to any products. NXP Semiconductors reserves the right to make changes
 * in the software without notification. NXP Semiconductors also makes no
 * representation or warranty that such application will be suitable for the
 * specified use without further testing or modification.
 *
 * @par
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, under NXP Semiconductors' and its
 * licensor's relevant copyrights in the software, without fee, provided that it
 * is used in conjunction with NXP Semiconductors microcontrollers.  This
 * copyright, permission, and disclaimer notice must appear in all copies of
 * this code.
 */
#include "board.h"
#include <string.h>
#include "aes.h"
/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/

#define TICKRATE_HZ			1000	/* 1000 ticks per second */

/* UART definitions */
#define LPC_UART				LPC_USART0
#define UARTx_IRQn			USART0_IRQn

/* AES definitions */
#define	CYPHER_CT			16

/* Memory location of the generated random numbers */
uint32_t *RANDOM_NUM = (uint32_t *) 0x40045050;

uint8_t rng_key[CYPHER_CT];
uint32_t rnum[4];

enum { OTP_KEY1=0, OTP_KEY2=1 };
typedef enum { MODE_NONE, MODE_ECB, MODE_CBC } ENCRYPT_T;
typedef enum { KEY_SW, KEY_OTP, KEY_RNG } KEY_T;
typedef struct {
	ENCRYPT_T	encryption;
	ENCRYPT_T	decryption;
	KEY_T		key_src;
	uint32_t	error;
	bool		status;
} CRYPT_CTRL_T;

typedef struct {
	uint32_t	src_chan;					// input:  source DMA channel number (0 - 7)
	uint32_t	dest_chan;					// input:  destination DMA channel number (0 to 7).
	uint32_t	aes_req_in;					// input:  AES input DMA request line (1 or 13)
	uint32_t	aes_req_out;				// input:  AES output DMA request lines (2 or 15)
	uint32_t 	channel_id;					// output: DMA channel ID
	uint32_t	error;						// output: error code returned by ROM calls
	bool		status;						// output: return status for the call
} DMA_CTRL_T;

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*
 * Test encryption (ECB mode) using the following test vectors taken from FIPS-197
 * (key loaded via application)
 *
 * http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb-128
 *
 * PLAINTEXT: 6bc1bee22e409f96e93d7e117393172a (127_0)
 * KEY:       2b7e151628aed2a6abf7158809cf4f3c (127_0)
 * RESULT:    3ad77bb40d7a3660a89ecaf32466ef97 (127_0)
 */
/* Send data to AES in Little Endian Format i.e. LSB in smallest address*/
static uint8_t SWKey[CYPHER_CT] = {
	0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab, 0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b
};

/* Send data to AES engine (Little Endian) */
static uint8_t InitVector[CYPHER_CT] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t PlainText[CYPHER_CT] = {
	0x2a, 0x17, 0x93, 0x73, 0x11, 0x7e, 0x3d, 0xe9, 0x96, 0x9f, 0x40, 0x2e, 0xe2, 0xbe, 0xc1, 0x6b
};
static uint8_t Expected_CypherText[CYPHER_CT] = {
	0x97, 0xef, 0x66, 0x24, 0xf3, 0xca, 0x9e, 0xa8, 0x60, 0x36, 0x7a, 0x0d, 0xb4, 0x7b, 0xd7, 0x3a
};


/* AES input and output for Software AES */
static uint8_t SWKey1[CYPHER_CT]      = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static uint8_t PlainText1[CYPHER_CT]  = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
static uint8_t Result1[CYPHER_CT]     = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
static uint8_t CypherText1[CYPHER_CT];
static uint8_t Result2[CYPHER_CT];
static uint8_t Temp_PlainText[CYPHER_CT];
static uint8_t CypherText[CYPHER_CT];
unsigned long t1, t2, t3, t4, swclkcycles_encrypt,swclkcycles_decrypt,hwclkcycles_encrypt,hwclkcycles_decrypt;
float sw_hw_ratio;
aes_ctx ctx_encrypt;

/* Encryption/Decryption options */
#define SW_ENCRYPT				1
#define SW_DECRYPT				0
#define HW_ECB_ENCRYPT			1
#define HW_ECB_DECRYPT			0
#define HW_CBC_ENCRYPT			0
#define HW_CBC_DECRYPT			0
#define HW_ECB_ENCRYPT_DMA		0
#define HW_ECB_DECRYPT_DMA		0
#define HW_CBC_ENCRYPT_DMA		0
#define HW_CBC_DECRYPT_DMA		0

/*****************************************************************************
 * Private functions
 ****************************************************************************/

/*****************************************************************************
 * Public functions
 ****************************************************************************/

/**
 * @brief	Handle interrupt from SysTick timer
 *			Run the tick every 500ms.
 * @return	Nothing
 */
static uint32_t tick_ct = 0;
void SysTick_Handler(void)
{
	tick_ct++;
	if ((tick_ct % 500) == 0) {
		Board_LED_Toggle(0);
	}
}

/**
 * @brief	Initialize the DMA control structure
 * @return	Nothing
 */
void init_dma_ctrl(DMA_CTRL_T* dma_ctrl)
{
	dma_ctrl->src_chan		= 0;				// input:  source DMA channel number (0 - 7)
	dma_ctrl->dest_chan		= 1;				// input:  destination DMA channel number (0 to 7).
	dma_ctrl->aes_req_in	= 1;				// input:  AES input DMA request line (1 or 13)
	dma_ctrl->aes_req_out	= 2;				// input:  AES output DMA request lines (2 or 15)
	dma_ctrl->channel_id	= 0;				// output: DMA channel ID
	dma_ctrl->error			= LPC_OK;			// output: error code returned by ROM calls
	dma_ctrl->status		= true;				// output: return status for the call
}

/**
 * @brief	Create channel_id
 *
 * The AES DMA functions use channel_id as an input argument.  This function
 * creates and returns channel_id based on the input arguments src_dma_chan_num,
 * dst_dma_chan_num, aes_in_req, and aes_out_req .
 *
 * @param	dma_ctrl: pointer to a DMA_CTRL_T structure
 * @return	nothing
 *
 */
void create_channel_id(DMA_CTRL_T* dma_ctrl)
{
	dma_ctrl->status = true;

	/* Setup source */
	dma_ctrl->channel_id = (dma_ctrl->src_chan << 16) | (dma_ctrl->aes_req_in << 24);
	switch (dma_ctrl->aes_req_in) {
	case 1:
		dma_ctrl->channel_id |= 3 << 28;
		break;

	case 13:
		dma_ctrl->channel_id |= 1 << 28;
		break;

	default:
		dma_ctrl->status = false;
	}

	/* Setup destination */
	dma_ctrl->channel_id |= (dma_ctrl->dest_chan) | (dma_ctrl->aes_req_out << 8);
	switch (dma_ctrl->aes_req_out) {
	case 2:
		dma_ctrl->channel_id |= 3 << 12;
		break;

	case 14:
		dma_ctrl->channel_id |= 1 << 12;
		break;

	default:
		dma_ctrl->status = false;
	}
}

/**
 * @brief	Test results of encrypt
 * @return	Nothing
 */
bool result_test_encrypt(void)
{
	return (memcmp(CypherText, Expected_CypherText, CYPHER_CT) == 0) ? true : false;
}
bool result_test_decrypt(void)
{
	return (memcmp(PlainText, Temp_PlainText, CYPHER_CT) == 0) ? true : false;
}


/**
 * @brief	Extract randomly generated key
 * @return	Nothing
 */
void extract_rngkey(void)
{
	int i=0, j, k;

	for (j = 0; j < 4; j++) {
		rnum[j] = *(RANDOM_NUM+j);
		for (k = 0; k < 4; k++) {
			rng_key[i++] = (0xFF & (rnum[j] >> (k << 3)));
		}
	}
}

/**
 * @brief	Execute encryption without DMA
 * @return	Nothing
 */
void encryption(CRYPT_CTRL_T* ctrl)
{
	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */
	ctrl->decryption = MODE_NONE;										/* Set decryption mode to none */

	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->encryption) {											/* Select encryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_ECB);	/* Set the mode to ECB encryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_CBC);	/* Set the mode to CBC encryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No encryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown encryption mode\r\n");						/* Report error */
		return;
	}
	t1 = LPC_TIMER0->TC;
	ctrl->error = Chip_AES_Operate(CypherText, PlainText, 1);			/* Run the AES Engine */
	t2 = LPC_TIMER0->TC;
	hwclkcycles_encrypt = t2 - t1;
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	ctrl->status = true;												/* Set status */
}

/**
 * @brief	Execute decryption without DMA
 * @return	Nothing
 */
void decryption(CRYPT_CTRL_T* ctrl)
{
	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */

	if (ctrl->encryption != ctrl->decryption) {							/* Is decrypt the same as encrypt? */
		DEBUGOUT("Encrypt and Decrypt do not match\r\n");				/* Report error */
		return;
	}

	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->decryption) {											/* Select decryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_ECB);	/* Set the mode to ECB decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_CBC);	/* Set the mode to CBC decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No decryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown decryption mode\r\n");						/* Report error */
		return;
	}
	t1 = LPC_TIMER0->TC;
	ctrl->error = Chip_AES_Operate(Temp_PlainText, CypherText, 1);		/* Run the AES engine */
	t2 = LPC_TIMER0->TC;
	hwclkcycles_decrypt = t2 - t1;
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	ctrl->status = true;												/* Set status */
}

/**
 * @brief	Execute encryption with DMA
 * @return	Nothing
 */
void encryption_dma(CRYPT_CTRL_T* ctrl)
{
	DMA_CTRL_T	dma;
	
	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */
	ctrl->decryption = MODE_NONE;										/* Set decryption mode to none */

	init_dma_ctrl(&dma);												/* Initialize the DMA structure */
	create_channel_id(&dma);											/* create channel_id */
	
	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->encryption) {											/* Select encryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_ECB);	/* Set the AES mode */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_CBC);	/* Set the mode to CBC encryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No encryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown encryption mode\r\n");						/* Report error */
		return;
	}
	ctrl->error = Chip_AES_Config_DMA(dma.channel_id);					/* Configure DMA channel to process AES block */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	t1 = LPC_TIMER0->TC;
	ctrl->error = Chip_AES_OperateDMA(dma.channel_id, CypherText, PlainText, 1);	/* Enable DMA, and start AES operation */
	t2 = LPC_TIMER0->TC;
	hwclkcycles_encrypt = t2 - t1;
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	while ((Chip_AES_GetStatusDMA(dma.channel_id)) != 0) {}					/* Wait for DMA to complete */
	ctrl->status = true;												/* Set status */
}

/**
 * @brief	Execute decryption with DMA
 * @return	Nothing
 */
void decryption_dma(CRYPT_CTRL_T* ctrl)
{
	DMA_CTRL_T	dma;

	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */

	init_dma_ctrl(&dma);												/* Initialize the DMA structure */
	create_channel_id(&dma);											/* create channel_id */

	if (ctrl->encryption != ctrl->decryption) {							/* Is decrypt the same as encrypt? */
		DEBUGOUT("Encrypt and Decrypt do not match\r\n");				/* Report error */
		return;
	}

	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->decryption) {											/* Select decryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_ECB);	/* Set the mode to ECB decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_CBC);	/* Set the mode to CBC decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No decryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown decryption mode\r\n");						/* Report error */
		return;
	}
	ctrl->error = Chip_AES_Config_DMA(dma.channel_id);					/* Configure DMA channel to process AES block */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	t1 = LPC_TIMER0->TC;
	ctrl->error = Chip_AES_OperateDMA(dma.channel_id, Temp_PlainText, CypherText, 1);	/* Enable DMA, and start AES operation */
	t2 = LPC_TIMER0->TC;
	hwclkcycles_decrypt = t2 - t1;
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	while ((Chip_AES_GetStatusDMA(dma.channel_id)) != 0) {}				/* Wait for DMA to complete */
	ctrl->status = true;												/* Set status */

}


/**
 * @brief	main routine for blinky example
 * @return	Function should not exit.
 */
int main(void)
{

	CRYPT_CTRL_T enc_ctrl;
	
	SystemCoreClockUpdate();
	Board_Init();
	Board_UART_Init(LPC_UART);
	Chip_UART_Init(LPC_UART);
	Chip_UART_SetBaud(LPC_UART, 115200);
	Chip_UART_ConfigData(LPC_UART, UART_LCR_WLEN8 | UART_LCR_SBS_1BIT);	/* Default 8-N-1 */
	Chip_UART_TXEnable(LPC_UART);
	Chip_UART_SetupFIFOS(LPC_UART, (UART_FCR_FIFO_EN | UART_FCR_RX_RS |
									UART_FCR_TX_RS | UART_FCR_DMAMODE_SEL | UART_FCR_TRG_LEV0));
	Chip_UART_IntEnable(LPC_UART, (UART_IER_ABEOINT | UART_IER_ABTOINT));
	NVIC_SetPriority(UARTx_IRQn, 1);
	NVIC_EnableIRQ(UARTx_IRQn);

	/* Enable and setup SysTick Timer at a periodic rate */
	//SysTick_Config(SystemCoreClock / TICKRATE_HZ);

	Chip_OTP_Init();

	Chip_AES_Init();// Initialize AES block
	DEBUGOUT("AES Engine Initialized...... \r\n");
	DEBUGOUT("\r\n\t\t\t\tPerformance of Hardware Vs Software AES\r\n");
	
	LPC_TIMER0->TCR = 1;
	
	while (1) 
	{

#if SW_ENCRYPT		
		/* Test software encryption */
		DEBUGOUT("\n\n\r--------------------------------------------------------------\n");
		DEBUGOUT("\n\r\t\tSOFTWARE ENCRYPTION");
		aes_set_encrypt_key(SWKey1, sizeof(SWKey1), &ctx_encrypt);
		t3 = LPC_TIMER0->TC; // Timer start
		aes_encrypt_block((uint8_t *)PlainText1, CypherText1, &ctx_encrypt);
		t4 = LPC_TIMER0->TC; // Timer end
		swclkcycles_encrypt = t4 - t3; // Number of clock cycles taken for AES encryption 
		DEBUGOUT("\n\r Software  AES Encryption: %lu clock cycles\r\n",swclkcycles_encrypt);
		if ( memcmp(CypherText1, Result1, sizeof(Result1) ) != 0) {
			while(1);
		}
#endif		

#if SW_DECRYPT
		aes_set_decrypt_key(SWKey1, sizeof(SWKey1), &ctx_encrypt);
		t3 = LPC_TIMER0->TC; // Timer start
		aes_decrypt_block((uint8_t *)CypherText1, Result2, &ctx_encrypt);
		t4 = LPC_TIMER0->TC; // Timer end
		swclkcycles_decrypt = t4 - t3; // Number of clock cycles taken for AES decryption 
		DEBUGOUT("\n\r Software  AES Decryption: %lu clock cycles\r\n",swclkcycles_decrypt);
		if ( memcmp(PlainText1, Result2, sizeof(Result2) ) != 0) 
		{
			while(1);
		}
#endif		
		
		DEBUGOUT("\n\r\t\tHARDWARE ENCRYPTION");
#if HW_ECB_ENCRYPT
		// Encryption using ECB mode without DMA
		enc_ctrl.encryption = MODE_ECB;
		enc_ctrl.key_src = KEY_SW;
		encryption(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r ECB mode encryption without DMA\t:%lu clock cycles\r\n", hwclkcycles_encrypt);
		}
		else {
			DEBUGOUT("\r\nAES Encryption in ECB mode without DMA failed\r\n");
		}
#endif		
		
#if HW_ECB_DECRYPT		
		// Decryption using ECB mode without DMA
		enc_ctrl.decryption = MODE_ECB;
		enc_ctrl.key_src = KEY_SW;
		decryption(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r ECB mode decryption without DMA\t:%lu clock cycles\r\n", hwclkcycles_decrypt);
		}
		else {
			DEBUGOUT("\r\nAES Decryption in ECB mode without DMA failed\r\n");
		}
#endif
		
#if HW_CBC_ENCRYPT		
		// Encryption using CBC mode without DMA
		enc_ctrl.encryption = MODE_CBC;
		enc_ctrl.key_src = KEY_SW;
		encryption(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r CBC mode encryption without DMA\t:%lu clock cycles\r\n", hwclkcycles_encrypt);
		}
		else {
			DEBUGOUT("\r\nAES Encryption in CBC mode without DMA failed\r\n");
		}
#endif

#if HW_CBC_DECRYPT		
		// Decryption using CBC mode without DMA
		enc_ctrl.decryption = MODE_CBC;
		enc_ctrl.key_src = KEY_SW;
		decryption(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r CBC mode decryption without DMA\t:%lu clock cycles\r\n", hwclkcycles_decrypt);
		}
		else {
			DEBUGOUT("\r\nAES Decryption in CBC mode without DMA failed\r\n");
		}
#endif

#if HW_ECB_ENCRYPT_DMA		
		// Encryption using ECB mode with DMA
		enc_ctrl.encryption = MODE_ECB;
		enc_ctrl.key_src = KEY_SW;
		encryption_dma(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r ECB mode encryption with DMA\t:%lu clock cycles\r\n", hwclkcycles_encrypt);
		}
		else {
			DEBUGOUT("\r\nAES Encryption in ECB mode with DMA failed\r\n");
		}
#endif

#if HW_ECB_DECRYPT_DMA		
		// Decryption using ECB mode with DMA
		enc_ctrl.decryption = MODE_ECB;
		enc_ctrl.key_src = KEY_SW;
		decryption_dma(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r ECB mode decryption with DMA\t:%lu clock cycles\r\n", hwclkcycles_decrypt);
		}
		else {
			DEBUGOUT("\r\nAES Decryption in ECB mode with DMA failed\r\n");
		}

#endif
		
#if HW_CBC_ENCRYPT_DMA		
		// Encryption using CBC mode with DMA
		enc_ctrl.encryption = MODE_CBC;
		enc_ctrl.key_src = KEY_SW;
		encryption_dma(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r CBC mode encryption with DMA\t:%lu clock cycles\r\n", hwclkcycles_encrypt);
		}
		else {
			DEBUGOUT("\r\nAES Encryption in CBC mode with DMA failed\r\n");
		}
#endif

#if HW_CBC_DECRYPT_DMA		
		// Decryption using CBC mode with DMA
		enc_ctrl.decryption = MODE_CBC;
		enc_ctrl.key_src = KEY_SW;
		decryption_dma(&enc_ctrl);
		if (enc_ctrl.status == true) {
			DEBUGOUT("\n\r CBC mode decryption with DMA\t:%lu clock cycles\r\n", hwclkcycles_decrypt);
		}
		else {
			DEBUGOUT("\r\nAES Decryption in CBC mode with DMA passed\r\n");
		}
#endif
		
		DEBUGOUT("\n\r Performance of Software AES Vs Hardware AES");
		sw_hw_ratio = ((float)swclkcycles_encrypt / (float)hwclkcycles_encrypt);
		DEBUGOUT("\n\r Encryption Ratio of SW / HW clock cycles %lu/%lu = %.2f",swclkcycles_encrypt,hwclkcycles_encrypt,sw_hw_ratio);
		sw_hw_ratio = ((float)swclkcycles_decrypt / (float)hwclkcycles_decrypt);
		DEBUGOUT("\n\r Decryption Ratio of SW / HW clock cycles %lu/%lu = %.2f",swclkcycles_decrypt,hwclkcycles_decrypt,sw_hw_ratio);
		DEBUGOUT("\n\n\r--------------------------------------------------------------\n");
		
	}
}
