#ifndef LYRA2RE_H
#define LYRA2RE_H

#ifdef __cplusplus
extern "C" {
#endif

void lyra2re_hash(const char* input, char* output, unsigned long len);
void lyra2re2_hash(const char* input, char* output, unsigned long len);

#ifdef __cplusplus
}
#endif

#endif
