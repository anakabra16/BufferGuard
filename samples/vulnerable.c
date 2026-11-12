#include <stdio.h>
#include <string.h>

int main(void) {
    char input[64];
    char buffer[16];

    printf("Enter text: ");

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }

    input[strcspn(input, "\n")] = '\0';

    // Unsafe: source may contain more data than buffer can hold.
    strcpy(buffer, input);

    printf("Copied text: %s\n", buffer);

    return 0;
}
