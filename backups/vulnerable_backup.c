
#include <stdio.h>
#include <string.h>

int main(void) {
    char input[16];

    printf("Enter text (maximum 15 characters): ");

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }

    input[strcspn(input, "\n")] = '\0';

    printf("You entered: %s\n", input);
    return 0;
}
