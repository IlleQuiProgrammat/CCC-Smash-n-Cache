#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define STACK_CANARY 0x11223344
#define FLAG "CCCCTF{SAMPLE_FLAG}"

#define CANARY_CHECK_FAIL 1
#define CANARY_CHECK_SUCCESS 0

char* read_input() {
    char* inp = malloc(258);
    puts("Welcome, please enter your unique product code to be added to our system. A reminder of the product code format is N sets of 4 numbers, please omit the `-'s.");
while (1) {
    fgets(inp, 258, stdin);
    if (strlen(inp) % 4 != 1) {
        puts("Error, input not a multiple of 4, please re-enter");
    } else {
        return inp;
    }
  }
}

void print_flag() {
    puts(FLAG);
}

int check_equiv(uint8_t a, uint8_t b) {
    if (a < b) {
        sleep(2);
        return CANARY_CHECK_FAIL;
    } else if (a > b) {
        sleep(5);
        return CANARY_CHECK_FAIL;
    } else {
        return CANARY_CHECK_SUCCESS;
    }
}

int check_canary(volatile int* canary) {
    int res = CANARY_CHECK_SUCCESS;
    res |= check_equiv((*canary >> 24) & 0xFF, (STACK_CANARY >> 24) & 0xFF);
    res |= check_equiv((*canary >> 16) & 0xFF, (STACK_CANARY >> 16) & 0xFF);
    res |= check_equiv((*canary >> 8) & 0xFF, (STACK_CANARY >> 8) & 0xFF);
    res |= check_equiv( *canary & 0xFF, STACK_CANARY & 0xFF);
    return res;
}

char** glob_argv;

void secure_code_exec() {
    struct {
    char result[248];
    volatile uint32_t canary;
    volatile uint32_t changeme;
    volatile uint32_t some_data; // stop overwrite of EIP whilst also allowing input
    }__attribute__((packed)) data;
    data.canary = STACK_CANARY;
    data.changeme = 0;
    char* product_code = read_input();
    strcpy(data.result, product_code);
    puts("Thank you for your money, we will process this at the end of the day");
    if (check_canary(&(data.canary)) == CANARY_CHECK_FAIL) {
        printf("*** stack smashing detected ***: %s terminated\n", glob_argv[0]);
        exit(-1);
    }
    if (data.changeme != 0) {
      print_flag();
    }
    free(product_code);
}

int main(int argc, char** argv) {
    glob_argv = argv;
    secure_code_exec();
    return 0;
}
