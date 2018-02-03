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
		uint32_t fp;
		int pos = CalculateFP(key, fp);	

#ifdef SIMD_ON
		const __m256i item = _mm256_set1_epi32((int)fp);
		__m256i *keys_p = (__m256i *)(buckets[pos].key);
		int matched = 0;

		__m256i a_comp = _mm256_cmpeq_epi32(item, keys_p[0]);
		matched = _mm256_movemask_ps((__m256)a_comp);

		if (matched != 0)
		{
			int matched_index = _tzcnt_u32((uint32_t)matched);
			buckets[pos].val[matched_index] += f;
			return 0;
		}

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
#else
		int min_counter = -1;
		uint32_t min_counter_val = 0x7FFFFFFF;
		for(int i = 0; i < MAX_VALID_COUNTER; ++i)
		{
			if(buckets[pos].key[i] == fp)
			{
				buckets[pos].val[i] += f;
				return 0;
			}
			int tmp_val = GetCounterVal(buckets[pos].val[i]);

			if(min_counter_val > tmp_val)
			{
				min_counter_val = tmp_val;
				min_counter = i;
			}
		}	    
#endif

		if(min_counter_val == 0)	
		{
			buckets[pos].key[min_counter] = fp;
			buckets[pos].val[min_counter] = f;
			return 0;
		}

		uint32_t guard_val = buckets[pos].val[MAX_VALID_COUNTER];
		guard_val = UPDATE_GUARD_VAL(guard_val);


		if(!JUDGE_IF_SWAP(GetCounterVal(min_counter_val), guard_val))
		{
			buckets[pos].val[MAX_VALID_COUNTER] = guard_val;
			return 2;
		}


		*((uint32_t*)swap_key) = buckets[pos].key[min_counter];
		swap_val = buckets[pos].val[min_counter];


		buckets[pos].val[MAX_VALID_COUNTER] = 0;


		buckets[pos].key[min_counter] = fp;
		buckets[pos].val[min_counter] = 0x80000001;

		return 1;
	}

	int quick_insert(uint8_t *key, uint32_t f = 1)
	{
		uint32_t fp;
		int pos = CalculateFP(key, fp);	

		const __m256i item = _mm256_set1_epi32((int)fp);
		__m256i *keys_p = (__m256i *)(buckets[pos].key);
		int matched = 0;

		__m256i a_comp = _mm256_cmpeq_epi32(item, keys_p[0]);
		matched = _mm256_movemask_ps((__m256)a_comp);

		if (matched != 0)
		{
			int matched_index = _tzcnt_u32((uint32_t)matched);
			buckets[pos].val[matched_index] += f;
			return 0;
		}

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


		if(min_counter_val == 0)	
		{
			buckets[pos].key[min_counter] = fp;
			buckets[pos].val[min_counter] = f;
			return 0;
		}

	
		uint32_t guard_val = buckets[pos].val[MAX_VALID_COUNTER];
		guard_val = UPDATE_GUARD_VAL(guard_val);


		if(!JUDGE_IF_SWAP(min_counter_val, guard_val))
		{
			buckets[pos].val[MAX_VALID_COUNTER] = guard_val;
			return 2;
		}


		buckets[pos].val[MAX_VALID_COUNTER] = 0;

		buckets[pos].key[min_counter] = fp;
		return 1;
	}

	uint32_t query(uint8_t *key)
	{
		uint32_t fp;
		int pos = CalculateFP(key, fp);

		for(int i = 0; i < MAX_VALID_COUNTER; ++i)
			if(buckets[pos].key[i] == fp)
				return buckets[pos].val[i];

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


	int count_high_1_bits()
	{
		int result = 0;
		for(int i = 0; i < bucket_num; ++i)
			for(int j = 0; j < MAX_VALID_COUNTER; ++j)
				if(HIGHEST_BIT_IS_1(buckets[i].val[j]))
					result++;
		return result;
	}
};









#endif