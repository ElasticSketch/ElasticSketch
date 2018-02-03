#ifndef _PARAM_H_
#define _PARAM_H_

#include "BOBHash32.h"

#include <x86intrin.h>
#include <string.h>
#include <stdint.h>
#include <random>
#include <string>
#include <memory>

#define COUNTER_PER_BUCKET 8
#define MAX_VALID_COUNTER 7

#define ALIGNMENT 64

#define COUNTER_PER_WORD 8
#define BIT_TO_DETERMINE_COUNTER 3
#define K_HASH_WORD 1


#define KEY_LENGTH_4 4
#define KEY_LENGTH_13 13

/* 计算fp对应的bucket的值 */
#define CONSTANT_NUMBER 2654435761u
#define CalculateBucketPos(fp) (((fp) * CONSTANT_NUMBER) >> 15)

/* 获取counter的真实值 */
#define GetCounterVal(val) ((uint32_t)((val) & 0x7FFFFFFF))

/* 判断min_val和guard_val关系的宏 */
// #define JUDGE_IF_SWAP(min_val, guard_val) ((guard_val) > ((min_val) * (min_val)))
#define JUDGE_IF_SWAP(min_val, guard_val) ((guard_val) > ((min_val) << 3))

/* 更新guard_val的宏 */
// #define UPDATE_GUARD_VAL(guard_val) ((guard_val) + 1 + ((guard_val) >> 1))
#define UPDATE_GUARD_VAL(guard_val) ((guard_val) + 1)

/* 被替换出去的流的size小于这个值的时候，不改变新值的最高位 */
#define SWAP_MIN_VAL_THRESHOLD 5

/* 判断一个uint32_t的最高位是不是1 */
#define HIGHEST_BIT_IS_1(val) ((val) & 0x80000000)



struct Bucket
{
	uint32_t key[COUNTER_PER_BUCKET];
	uint32_t val[COUNTER_PER_BUCKET];
};


#endif
