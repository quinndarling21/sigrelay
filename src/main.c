#include <stdio.h>

#include "sigrelay/sigrelay.h"

int main(void)
{
    printf("sigrelayd %s\n", sigrelay_version());
    return 0;
}
