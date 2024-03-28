/******************************************************************************
* File Name: main.c
*
* Description: This code provides an implementation of AES Cryptolite,
* demonstrating how to encrypt and decrypt data using the CTR and CFB modes.
*
* Related Document: See README.md
*
*******************************************************************************
* Copyright 2021-2024, Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
*
* This software, including source code, documentation and related
* materials ("Software") is owned by Cypress Semiconductor Corporation
* or one of its affiliates ("Cypress") and is protected by and subject to
* worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software
* source code solely for use in connection with Cypress's
* integrated circuit products.  Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*******************************************************************************/

/*******************************************************************************
*Header Files
*******************************************************************************/

#include "cyhal.h"
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "cy_pdl.h"
#include <string.h>

/*******************************************************************************
* Macros
*******************************************************************************/
/* The input message size (inclusive of the string terminating character '\0').
 * Edit this macro to suit your message size.
 */
#define MAX_MESSAGE_SIZE                     (100u)

/* Size of the message block that can be processed by Cryptolite hardware for
 * AES encryption.
 */
#define AES128_ENCRYPTION_LENGTH             (uint32_t)(16u)

#define AES128_KEY_LENGTH                    (uint32_t)(16u)

/* Number of bytes per line to be printed on the UART terminal. */
#define BYTES_PER_LINE                       (16u)

/* Time to wait to receive a character from UART terminal. */
#define UART_INPUT_TIMEOUT_MS                (1u)

/* Available commands */
#define CRYPTOLITE_AES_CTR ('1')
#define CRYPTOLITE_AES_CFB ('2')

/*******************************************************************************
* Data type definitions
*******************************************************************************/
/* Data type definition to track the state machine accepting the user message */
typedef enum
{
    MESSAGE_ENTER_NEW,
    MESSAGE_READY
} message_status_t;


/*******************************************************************************
* Global Variables
*******************************************************************************/

/* UART object used for reading character from terminal */
extern cyhal_uart_t cy_retarget_io_uart_obj;


/* Variables to hold the user message and the corresponding encrypted message */
static uint8_t message[MAX_MESSAGE_SIZE];
static uint8_t encrypted_msg[MAX_MESSAGE_SIZE];
static uint8_t decrypted_msg[MAX_MESSAGE_SIZE];

/* Key used for AES encryption*/
static uint8_t aes_key[AES128_KEY_LENGTH] = {0xAA, 0xBB, 0xCC, 0xDD,
                                            0xEE, 0xFF, 0xFF, 0xEE,
                                            0xDD, 0xCC, 0xBB, 0xAA,
                                            0xAA, 0xBB, 0xCC, 0xDD,};



/******************************CTR Encryption**********************************/
/* AES CFB MODE Initialization Vector*/
static uint8_t AesCtrIV[] =
{
    0x00,0x01,0x02,0x03,
    0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,
    0x0C,0x0D,0x0E,0x0F,
};

static uint8_t AesCtrIV_copied[16];

/********************************CFB Encryption********************************/
/* AES CFB MODE Initialization Vector */
static uint8_t AesCfbIV[] =
{
    0x00,0x01,0x02,0x03,
    0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,
    0x0C,0x0D,0x0E,0x0F,
};

static uint8_t AesCfbIV_copied[16];

/******************************************************************************
 *Function Definitions
 ******************************************************************************/

void print_data(uint8_t* data, uint8_t len);
void encrypt_message_cfb(uint8_t* message, uint8_t size);
void decrypt_message_cfb(uint8_t* message, uint8_t size);
void encrypt_message_ctr(uint8_t* message, uint8_t size);
void decrypt_message_ctr(uint8_t* message, uint8_t size);


/*******************************************************************************
* Function Name: main
********************************************************************************
* Summary:
* This is the main function and entry point to the application.
*
* Parameters:
*  void
*
* Return:
*  int
*
*******************************************************************************/

int main(void)
{
    cy_rslt_t result;

    uint8_t dst_cmd;
    /* Variable to track the status of the message entered by the user */
    message_status_t msg_status = MESSAGE_ENTER_NEW;
    uint8_t msg_size = 0;

    /* Initialize the device and board peripherals */
    result = cybsp_init();
    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    /* Initialize retarget-io to use the debug UART port */
    result = cy_retarget_io_init_fc(    CYBSP_DEBUG_UART_TX,
                                        CYBSP_DEBUG_UART_RX,
                                        CYBSP_DEBUG_UART_CTS,
                                        CYBSP_DEBUG_UART_RTS,
                                        CY_RETARGET_IO_BAUDRATE);
    /* retarget-io init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }
    printf("*****************CE : Cryptolite AES *****************\r\n");
    printf("\r\n\nKey used for Encryption:\r\n");
    print_data(aes_key, AES128_KEY_LENGTH);
    printf("\n\rEnter the message:\r\n");
    for (;;)
    {
        switch (msg_status)
        {
            case MESSAGE_ENTER_NEW:
            {
                result = cyhal_uart_getc(&cy_retarget_io_uart_obj,
                                        &message[msg_size],
                                        UART_INPUT_TIMEOUT_MS);
                if (result == CY_RSLT_SUCCESS)
                    {
                    /* Check if the ENTER Key is pressed. If pressed, set the
                       message status as MESSAGE_READY.*/
                    if (message[msg_size] == '\r' || message[msg_size] == '\n')
                    {
                        message[msg_size]='\0';
                        msg_status = MESSAGE_READY;
                    }
                    else
                    {
                        cyhal_uart_putc(&cy_retarget_io_uart_obj,
                                        message[msg_size]);

                        /* Check if Backspace is pressed by the user. */
                        if(message[msg_size] != '\b')
                        {
                            msg_size++;
                        }
                        else
                        {
                            if(msg_size > 0)
                            {
                                msg_size--;
                            }
                        }
                        /*Check if size of the message  exceeds MAX_MESSAGE_SIZE
                        (inclusive of the string terminating character '\0').*/
                        if (msg_size > (MAX_MESSAGE_SIZE - 1))
                        {
                        printf("\r\n\nMessage length exceeds %d characters!!!"\
                        " Please enter a shorter message\r\nor edit the macro "\
                        "MAX_MESSAGE_SIZE to suit your message size\r\n", MAX_MESSAGE_SIZE);

                        /* Clear the message buffer and set the msg_status to
                            accept new message from the user. */
                        msg_status = MESSAGE_ENTER_NEW;
                        memset(message, 0, MAX_MESSAGE_SIZE);
                        msg_size = 0;
                        printf("\r\nEnter the message when more than limit:\r\n");
                        break;
                        }
                    }
                    }
                    break;
                }

                case MESSAGE_READY:
                {
                printf("\n\n\r Choose one of the following AES Mode :\r\n");
                printf("\n\r (1) CTR (Counter) mode\r\n");
                printf("\n\r (2) CFB (Cipher Feedback Block) mode\r\n");
                while(cyhal_uart_getc(&cy_retarget_io_uart_obj, &dst_cmd, 1)!= CY_RSLT_SUCCESS);
                cyhal_uart_putc(&cy_retarget_io_uart_obj, dst_cmd);

                if (CRYPTOLITE_AES_CTR == dst_cmd)
                {
                    printf("\n\r[Command] : AES CTR Mode\r\n");
                    encrypt_message_ctr(message, msg_size);
                    decrypt_message_ctr(message, msg_size);
                }
                else if (CRYPTOLITE_AES_CFB == dst_cmd)
                {
                    printf("\n\r[Command] : AES CFB Mode\r\n");
                    encrypt_message_cfb(message, msg_size);
                    decrypt_message_cfb(message, msg_size);
                }

                /* Clear the message buffer and set the msg_status to accept
                * new message from the user.
                */

                msg_status = MESSAGE_ENTER_NEW;
                memset(message, 0, MAX_MESSAGE_SIZE);
                msg_size = 0;
                printf("\n\n\rEnter the message again to accept:\r\n");
                break;
                }
            }
        }

}

/*******************************************************************************
* Function Name: print_data()
********************************************************************************
* Summary: Function used to display the data in hexadecimal format
*
* Parameters:
*  uint8_t* data - Pointer to location of data to be printed
*  uint8_t  len  - length of data to be printed
*
* Return:
*  void
*
*******************************************************************************/

void print_data(uint8_t* data, uint8_t len)
{
    char print[10];
    for (uint32 i=0; i < len; i++)
    {
        if ((i % BYTES_PER_LINE) == 0)
        {
            printf("\r\n");
        }
        snprintf(print,10,"0x%02X ", *(data+i));
        printf("%s", print);
    }
    printf("\r\n");
}

/*******************************************************************************
* Function Name: encrypt_message_cfb
********************************************************************************
* Summary: Function used to encrypt the message through cfb mode.
*
* Parameters:
*  char * message - pointer to the message to be encrypted
*  uint8_t size   - size of message to be encrypted.
*
* Return:
*  void
*
*******************************************************************************/


void encrypt_message_cfb(uint8_t* message, uint8_t size)
{
    cy_stc_cryptolite_aes_state_t aes_state;
    cy_stc_cryptolite_aes_buffers_t aesBuffers;
    uint8_t aes_block_count = 0;
    cy_en_cryptolite_status_t res;
    void* result;

    aes_block_count =  (size % AES128_ENCRYPTION_LENGTH == 0) ?
                       (size / AES128_ENCRYPTION_LENGTH)
                       : (1 + size / AES128_ENCRYPTION_LENGTH);

    /* Initializes the AES operation by setting key and key length */
    res = Cy_Cryptolite_Aes_Init(CRYPTOLITE, aes_key, &aes_state, &aesBuffers);
    if(res!=CY_CRYPTOLITE_SUCCESS)
    {
        CY_ASSERT(0);
    }

    result = memcpy(AesCfbIV_copied, AesCfbIV, sizeof(AesCfbIV));
    if(result == NULL)
    {
        perror("Memory failed\r\n");
    }

    res = Cy_Cryptolite_Aes_Cfb(  CRYPTOLITE,
                            CY_CRYPTOLITE_ENCRYPT,
                            aes_block_count * AES128_ENCRYPTION_LENGTH,
                            AesCfbIV_copied,
                            encrypted_msg,
                            message,
                            &aes_state);

    if(res!=CY_CRYPTOLITE_SUCCESS)
    {
        CY_ASSERT(0);
    }
    res = Cy_Cryptolite_Aes_Free(CRYPTOLITE,&aes_state);
    if(res!=CY_CRYPTOLITE_SUCCESS)
    {
        CY_ASSERT(0);
    }
    printf("\r\nResult of Encryption:\r\n");
    print_data((uint8_t*) encrypted_msg,
                aes_block_count * AES128_ENCRYPTION_LENGTH );

}

/*******************************************************************************
* Function Name: decrypt_message
********************************************************************************
* Summary: Function used to decrypt the message for cfb mode.
*
* Parameters:
*  char * message - pointer to the message to be decrypted
*  uint8_t size   - size of message to be decrypted.
*
* Return:
*  void
*
*******************************************************************************/

void decrypt_message_cfb(uint8_t* message, uint8_t size)
{
    cy_stc_cryptolite_aes_state_t aes_state;
    cy_stc_cryptolite_aes_buffers_t aesBuffers;
    uint8_t aes_block_count = 0;
    cy_en_cryptolite_status_t res;
    void* result;

    aes_block_count =  (size % AES128_ENCRYPTION_LENGTH == 0) ?
                       (size / AES128_ENCRYPTION_LENGTH)
                       : (1 + size / AES128_ENCRYPTION_LENGTH);

    /* Initializes the AES operation by setting key and key length */
    res = Cy_Cryptolite_Aes_Init(CRYPTOLITE, aes_key, &aes_state, &aesBuffers);
    if(res!=CY_CRYPTOLITE_SUCCESS)
    {
        CY_ASSERT(0);
    }
    /* Start decryption operation*/
    result = memcpy(AesCfbIV_copied, AesCfbIV, sizeof(AesCfbIV));
    if(result == NULL)
    {
       perror("Memory failed\r\n");
    }
    res = Cy_Cryptolite_Aes_Cfb(CRYPTOLITE,
                            CY_CRYPTOLITE_DECRYPT,
                            aes_block_count * AES128_ENCRYPTION_LENGTH,
                            AesCfbIV_copied,
                            decrypted_msg,
                            encrypted_msg,
                            &aes_state);
    if(res!=CY_CRYPTOLITE_SUCCESS)
        {
            CY_ASSERT(0);
        }
    res = Cy_Cryptolite_Aes_Free(CRYPTOLITE,&aes_state);
    if(res!=CY_CRYPTOLITE_SUCCESS)
        {
            CY_ASSERT(0);
        }
    decrypted_msg[size]='\0';
    /* Print the decrypted message on the UART terminal */
    printf("\r\nResult of Decryption:\r\n\n");
    printf("%s", decrypted_msg);

}

/*******************************************************************************
* Function Name: encrypt_message_cfb
********************************************************************************
* Summary: Function used to encrypt the message through ctr mode.
*
* Parameters:
*  char * message - pointer to the message to be encrypted
*  uint8_t size   - size of message to be encrypted.
*
* Return:
*  void
*
*******************************************************************************/

void encrypt_message_ctr(uint8_t* message, uint8_t size)
{
    uint32_t srcOffset;
    cy_stc_cryptolite_aes_state_t aes_state;
    cy_stc_cryptolite_aes_buffers_t aesBuffers;
    uint8_t aes_block_count = 0;
    cy_en_cryptolite_status_t res;
    void* result;

    aes_block_count =  (size % AES128_ENCRYPTION_LENGTH == 0) ?
                       (size / AES128_ENCRYPTION_LENGTH)
                       : (1 + size / AES128_ENCRYPTION_LENGTH);
    /* Initializes the AES operation by setting key and key length */
     res = Cy_Cryptolite_Aes_Init(CRYPTOLITE, aes_key, &aes_state, &aesBuffers);
     if(res!=CY_CRYPTOLITE_SUCCESS)
     {
       CY_ASSERT(0);
     }

     srcOffset = 0;
     result = memcpy(AesCtrIV_copied, AesCtrIV, sizeof(AesCtrIV));
     if(result == NULL)
     {
       perror("Memory failed\r\n");
     }
     res = Cy_Cryptolite_Aes_Ctr( CRYPTOLITE,
                            aes_block_count * AES128_ENCRYPTION_LENGTH,
                            &srcOffset,
                            AesCtrIV_copied,
                            encrypted_msg,
                            message,
                            &aes_state);
     if(res!=CY_CRYPTOLITE_SUCCESS)
     {
       CY_ASSERT(0);
     }
     res = Cy_Cryptolite_Aes_Free(CRYPTOLITE,&aes_state);
     if(res!=CY_CRYPTOLITE_SUCCESS)
     {
       CY_ASSERT(0);
     }
     printf("\r\nResult of Encryption:\r\n");
     print_data((uint8_t*) encrypted_msg,
                aes_block_count * AES128_ENCRYPTION_LENGTH );

}

/*******************************************************************************
* Function Name: decrypt_message
********************************************************************************
* Summary: Function used to decrypt the message for ctr mode.
*
* Parameters:
*  char * message - pointer to the message to be decrypted
*  uint8_t size   - size of message to be decrypted.
*
* Return:
*  void
*
*******************************************************************************/

void decrypt_message_ctr(uint8_t* message, uint8_t size)
{
    uint32_t srcOffset;
    cy_stc_cryptolite_aes_state_t aes_state;
    cy_stc_cryptolite_aes_buffers_t aesBuffers;
    uint8_t aes_block_count = 0;
    cy_en_cryptolite_status_t res;
    void* result;
    aes_block_count =  (size % AES128_ENCRYPTION_LENGTH == 0) ?
                       (size / AES128_ENCRYPTION_LENGTH)
                       : (1 + size / AES128_ENCRYPTION_LENGTH);

    /* Initializes the AES operation by setting key and key length */
    res = Cy_Cryptolite_Aes_Init(CRYPTOLITE, aes_key, &aes_state, &aesBuffers);
    if(res!=CY_CRYPTOLITE_SUCCESS)
    {
        CY_ASSERT(0);
    }
    srcOffset = 0;
    /* Start decryption operation*/
    result = memcpy(AesCtrIV_copied, AesCtrIV, sizeof(AesCtrIV));
    if(result == NULL)
    {
        perror("Memory failed\r\n");
    }
    res = Cy_Cryptolite_Aes_Ctr(  CRYPTOLITE,
                            aes_block_count * AES128_ENCRYPTION_LENGTH,
                            &srcOffset,
                            AesCtrIV_copied,
                            decrypted_msg,
                            encrypted_msg,
                            &aes_state);
    if(res!=CY_CRYPTOLITE_SUCCESS)
    {
        CY_ASSERT(0);
    }
    res = Cy_Cryptolite_Aes_Free(CRYPTOLITE,&aes_state);
    if(res!=CY_CRYPTOLITE_SUCCESS)
    {
        CY_ASSERT(0);
    }
    decrypted_msg[size]='\0';
    /* Print the decrypted message on the UART terminal */
    printf("\r\nResult of Decryption:\r\n\n");
    printf("%s", decrypted_msg);

}

/* [] END OF FILE */
