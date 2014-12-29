#include <stdio.h>  /* for printf, fgets */
#include <stdlib.h>  /* for atoi */
#include <stdint.h> /* for uint32_t */
#include <safe_iop.h> /* for awesomeness */

int main(int argc, char **argv) {
  char buf[1024];
  uint32_t width = 0, height = 0, pixels = 0;
  printf("Please specify the width of the new image: ");
  width = strtoul(fgets(buf, 1023, stdin), NULL, 10);
  printf("Please specify the height of the new image: ");
  height = strtoul(fgets(buf, 1023, stdin), NULL, 10);
  if (safe_mul(&pixels, width, height)) {
    printf("The resulting image will have %u pixels.\n", pixels);
    return 0;
  } else {
    printf("Image size specified exceeds maximum size!\n");
    return 1;
  }
}
