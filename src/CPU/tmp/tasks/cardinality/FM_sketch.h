#ifndef _FM_SKETCH_4_H_
#define _FM_SKETCH_4_H_

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "BOBHash32.h"

template <int key_len, int tot_memory_in_bytes> class FMSketch {
        static constexpr int map_num = tot_memory_in_bytes >> 2;

        uint32_t bit_map[map_num];
        BOBHash32 *hash_gen[map_num];

      public:
        FMSketch() {
                memset(bit_map, 0, sizeof(uint32_t) * map_num);
                for (int i = 0; i < map_num; i++) {
                        auto idx = uint32_t(rand() % MAX_PRIME32);
                        hash_gen[i] = new BOBHash32(idx);
                }
        }
        ~FMSketch() {}
        void clear() { memset(bit_map, 0, sizeof(uint32_t) * map_num); }

        void insert(uint8_t *key) {
                for (int i = 0; i < map_num; i++) {
                        int hash_init =
                            hash_gen[i]->run((const char *)key, key_len);

                        int pos = 0;
                        for (int &j = pos; hash_init % 2 == 0; j++)
                                hash_init >>= 1;
                        bit_map[i] |= (1 << pos);
                }
        }

      public:
        string name = "FM";

        int get_cardinality() {
                int sum_pos = 0;
                for (int i = 0; i < map_num; i++) {
                        int pos = 0;
                        for (int &j = pos; j < 32 && (bit_map[i] & (1 << j)); j++)
                                ;
			sum_pos += pos;
                }
                double ave_pos = sum_pos / (double)map_num;

                return 1.2928 * pow(2, ave_pos);
        }
};

#endif
