#ifndef _ELEPHANT_PART_4_H_
#define _ELEPHANT_PART_4_H_

#include "param.h"

template<int bucket_num>
class ElephantPart_4
{
public:
	alignas(64) Bucket buckets[bucket_num];

	ElephantPart_4()
	{
		memset(buckets, 0, sizeof(Bucket) * bucket_num);
	}
	~ElephantPart_4(){}

	void clear()
	{
		memset(buckets, 0, sizeof(Bucket) * bucket_num);
	}

	int insert(uint8_t *key, uint8_t *swap_key, uint32_t &swap_val, uint32_t f = 1)
	{
	/* 先计算出fingerprint，以及pos */
		uint32_t fp;
		int pos = CalculateFP(key, fp);	

	/* 接着尝试匹配bucket里的fp */
		const __m256i item = _mm256_set1_epi32((int)fp);
		__m256i *keys_p = (__m256i *)(buckets[pos].key);
		int matched = 0;

		__m256i a_comp = _mm256_cmpeq_epi32(item, keys_p[0]);
		matched = _mm256_movemask_ps((__m256)a_comp);

		if (matched != 0)
		{
			//return 32 if input is zero;
			int matched_index = _tzcnt_u32((uint32_t)matched);
			buckets[pos].val[matched_index] += f;
			return 0;
		}

	/* 找最小counter */	
		// int min_counter = -1;
		// uint32_t min_counter_val = 0x7FFFFFFF;
		// for(int i = 0; i < MAX_VALID_COUNTER; ++i)
		// {
		// 	int tmp_val = GetCounterVal(buckets[pos].val[i]);

		// 	if(min_counter_val > tmp_val)
		// 	{
		// 		min_counter_val = tmp_val;
		// 		min_counter = i;
		// 	}
		// }
		const uint32_t mask_base = 0x7FFFFFFF;
		const __m256i *counters = (__m256i *)(buckets[pos].val);
		__m256 masks = (__m256)_mm256_set1_epi32(mask_base);
		__m256 results = (_mm256_and_ps(*(__m256*)counters, masks));
	    __m256 mask2 = (__m256)_mm256_set_epi32(mask_base, 0, 0, 0, 0, 0, 0, 0);
	    results = _mm256_or_ps(results, mask2);

	    __m128i low_part = _mm_castps_si128(_mm256_extractf128_ps(results, 0));
	    __m128i high_part = _mm_castps_si128(_mm256_extractf128_ps(results, 1));

	    __m128i x = _mm_min_epi32(low_part, high_part);
	    __m128i min1 = _mm_shuffle_epi32(x, _MM_SHUFFLE(0,0,3,2));
	    __m128i min2 = _mm_min_epi32(x,min1);
	    __m128i min3 = _mm_shuffle_epi32(min2, _MM_SHUFFLE(0,0,0,1));
	    __m128i min4 = _mm_min_epi32(min2,min3);
	    int min_counter_val = _mm_cvtsi128_si32(min4);

	    const __m256i ct_item = _mm256_set1_epi32(min_counter_val);
	    int ct_matched = 0;

	    __m256i ct_a_comp = _mm256_cmpeq_epi32(ct_item, (__m256i)results);
	    matched = _mm256_movemask_ps((__m256)ct_a_comp);
	    int min_counter = _tzcnt_u32((uint32_t)matched);

	/* 如果匹配插入失败，那么应该找空的bucket */
		if(min_counter_val == 0)		// 表示找到了空的counter
		{
			buckets[pos].key[min_counter] = fp;
			buckets[pos].val[min_counter] = f;
			return 0;
		}

	/* 如果没有空的counter，那么应该把第8个counter里的值+1，然后和最小counter的值比较 */
		uint32_t guard_val = buckets[pos].val[MAX_VALID_COUNTER];
		guard_val = UPDATE_GUARD_VAL(guard_val);

	/* 如果没有超过阈值，那么直接返回 */
		if(!JUDGE_IF_SWAP(GetCounterVal(min_counter_val), guard_val))
		{
			buckets[pos].val[MAX_VALID_COUNTER] = guard_val;
			return 2;
		}

	/* 如果超过了阈值，把最小的counter置为1，fp替换成现在的fp，并且清空第8个counter */
		/* 需要把这个key和val插入到小流部分，所以返回这个val用来表示需要交换 */
		*((uint32_t*)swap_key) = buckets[pos].key[min_counter];
		swap_val = buckets[pos].val[min_counter];

	/* 第8个counter */
		buckets[pos].val[MAX_VALID_COUNTER] = 0;

	/* 最小counter*/
		buckets[pos].key[min_counter] = fp;
		/* 如果被替换出去的val小于SWAP_MIN_VAL_THRESHOLD，那么不把新val的最高位置为1 */
			// buckets[pos].val[min_counter] = swap_val < SWAP_MIN_VAL_THRESHOLD ? 1 : 0x80000001;
		// if(swap_val != 1) //&& swap_val != 0x80000001)
		buckets[pos].val[min_counter] = 0x80000001;

		return 1;
	}

	int quick_insert(uint8_t *key, uint32_t f = 1)
	{
	/* 先计算出fingerprint，以及pos */
		uint32_t fp;
		int pos = CalculateFP(key, fp);	

	/* 接着尝试匹配bucket里的fp */
		const __m256i item = _mm256_set1_epi32((int)fp);
		__m256i *keys_p = (__m256i *)(buckets[pos].key);
		int matched = 0;

		__m256i a_comp = _mm256_cmpeq_epi32(item, keys_p[0]);
		matched = _mm256_movemask_ps((__m256)a_comp);

		if (matched != 0)
		{
			//return 32 if input is zero;
			int matched_index = _tzcnt_u32((uint32_t)matched);
			buckets[pos].val[matched_index] += f;
			return 0;
		}

	/* 找最小counter */	
		// int min_counter = -1;
		// uint32_t min_counter_val = 0x7FFFFFFF;
		// for(int i = 0; i < MAX_VALID_COUNTER; ++i)
		// {
		// 	int tmp_val = GetCounterVal(buckets[pos].val[i]);

		// 	if(min_counter_val > tmp_val)
		// 	{
		// 		min_counter_val = tmp_val;
		// 		min_counter = i;
		// 	}
		// }
		const uint32_t mask_base = 0x7FFFFFFF;
		const __m256i *counters = (__m256i *)(buckets[pos].val);
		__m256 masks = (__m256)_mm256_set1_epi32(mask_base);
		__m256 results = (_mm256_and_ps(*(__m256*)counters, masks));
	    __m256 mask2 = (__m256)_mm256_set_epi32(mask_base, 0, 0, 0, 0, 0, 0, 0);
	    results = _mm256_or_ps(results, mask2);

	    __m128i low_part = _mm_castps_si128(_mm256_extractf128_ps(results, 0));
	    __m128i high_part = _mm_castps_si128(_mm256_extractf128_ps(results, 1));

	    __m128i x = _mm_min_epi32(low_part, high_part);
	    __m128i min1 = _mm_shuffle_epi32(x, _MM_SHUFFLE(0,0,3,2));
	    __m128i min2 = _mm_min_epi32(x,min1);
	    __m128i min3 = _mm_shuffle_epi32(min2, _MM_SHUFFLE(0,0,0,1));
	    __m128i min4 = _mm_min_epi32(min2,min3);
	    int min_counter_val = _mm_cvtsi128_si32(min4);

	    const __m256i ct_item = _mm256_set1_epi32(min_counter_val);
	    int ct_matched = 0;

	    __m256i ct_a_comp = _mm256_cmpeq_epi32(ct_item, (__m256i)results);
	    matched = _mm256_movemask_ps((__m256)ct_a_comp);
	    int min_counter = _tzcnt_u32((uint32_t)matched);

	/* 如果匹配插入失败，那么应该找空的bucket */
		if(min_counter_val == 0)		// 表示找到了空的counter
		{
			buckets[pos].key[min_counter] = fp;
			buckets[pos].val[min_counter] = f;
			return 0;
		}

	/* 如果没有空的counter，那么应该把第8个counter里的值+1，然后和最小counter的值比较 */
		uint32_t guard_val = buckets[pos].val[MAX_VALID_COUNTER];
		guard_val = UPDATE_GUARD_VAL(guard_val);

	/* 如果没有超过阈值，那么直接返回 */
		if(!JUDGE_IF_SWAP(min_counter_val, guard_val))
		{
			buckets[pos].val[MAX_VALID_COUNTER] = guard_val;
			return 2;
		}

	/* 如果超过了阈值，把最小的counter置为1，fp替换成现在的fp，并且清空第8个counter */
		/* 需要把这个key和val插入到小流部分，所以返回这个val用来表示需要交换 */
		// *((uint32_t*)swap_key) = buckets[pos].key[min_counter];
		// swap_val = buckets[pos].val[min_counter];

		buckets[pos].val[MAX_VALID_COUNTER] = 0;

		buckets[pos].key[min_counter] = fp;
		/* 如果被替换出去的val小于SWAP_MIN_VAL_THRESHOLD，那么不把新val的最高位置为1 */
		// buckets[pos].val[min_counter] = swap_val < SWAP_MIN_VAL_THRESHOLD ? 1 : 0x80000001;
		// buckets[pos].val[min_counter] = 0x80000001;
		// buckets[pos].val[min_counter] = (buckets[pos].val[min_counter] & 0x7FFFFFFF) + 1;

		return 1;
	}

	uint32_t query(uint8_t *key)
	{
	/* 先计算出fingerprint，以及pos */
		uint32_t fp;
		int pos = CalculateFP(key, fp);

	/* 然后一个个匹配counter里的fp，这里可以用simd加速 */
		for(int i = 0; i < MAX_VALID_COUNTER; ++i)
			if(buckets[pos].key[i] == fp)
				return buckets[pos].val[i];

	/* 返回0表示没有查询到 */
		return 0;
	}

private:
	int CalculateFP(uint8_t *key, uint32_t &fp)
	{
		fp = *((uint32_t*)key);
		return CalculateBucketPos(fp) % bucket_num;
	}


public:
	int get_memory_usage()
	{
		return bucket_num * sizeof(Bucket);
	}
	int get_bucket_num()
	{
		return bucket_num;
	}
};









#endif
