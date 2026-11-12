
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 16

int main(void) {
    char input[BUFFER_SIZE];

    printf("Enter text (maximum %d characters): ", BUFFER_SIZE - 1);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    size_t length = strcspn(input, "\n");

    if (input[length] == '\n') {
        input[length] = '\0';
    } else {
        int next = getchar();

        if (next != EOF) {
            fprintf(stderr, "Input too long. Maximum is %d characters.\n",
                    BUFFER_SIZE - 1);
            return 1;
        }
    }

    printf("Input accepted: %s\n", input);
    return 0;
}
