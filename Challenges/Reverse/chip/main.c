#include <stdio.h>
#include <string.h>
#include "xxtea.h"

unsigned char encrypt_data[] = {0xf3, 0x76, 0xb6, 0xa5, 0x73, 0x0e, 0x31, 0xec, 0x5c, 0x63, 0x27, 0x06, 0x73, 0x81, 0xd4, 0x75, 0xd9, 0xf4, 0x94, 0x80, 0xca, 0x5c, 0x6d, 0x99, 0x54, 0x70, 0x51, 0x09, 0xd5, 0x14, 0x49, 0xf9, 0x03, 0x59, 0xee, 0xb2};

int main() {
    const char text[32];
    const char *key = "deadbeef05";
    printf("[flag] >>> ");
    scanf("%s", text);
    if ((int)(strlen(text)) != 32) {
        printf("[flag] <<< nope, Out of sync. %d", strlen(text));
        return 1;
    }
    size_t len;
    unsigned char *encrypt_inp = xxtea_encrypt(text, strlen(text), key, &len);
    // char *decrypt_data = xxtea_decrypt(encrypt_data, len, key, &len);
    //if (strncmp(text, decrypt_data, len) == 0) {
    //    printf("success!\n");
    for (int i = 0; i < len; i++)
        if (encrypt_data[i] != encrypt_inp[i]) {
            printf("[flag] <<< nope, Out of sync.");
	        return 1;
	    }
    printf("[flag] <<< right, congradulations!\n");
    //}
    //else {
    //    printf("fail!\n");
    //}
    free(encrypt_inp);
    //free(decrypt_data);
    return 0;
}
