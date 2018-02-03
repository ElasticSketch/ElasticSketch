#ifndef _ELEPHANT_PART_13_H_
#define _ELEPHANT_PART_13_H_

#include "param.h"

template<int bucket_num>
class ElephantPart_13
{
	BOBHash32 *fp_hash = NULL;
public:
	alignas(64) Bucket buckets[bucket_num];
	uint8_t key_stores[bucket_num][COUNTER_PER_BUCKET][KEY_LENGTH_13];

	ElephantPart_13()
	{
		memset(buckets, 0, sizeof(Bucket) * bucket_num);
		memset(key_stores, 0, sizeof(key_stores));

		std::random_device rd;
		fp_hash = new BOBHash32(rd() % MAX_PRIME32);
	}
	~ElephantPart_13()
	{
		delete fp_hash;
	}

	void clear()
	{
		memset(buckets, 0, sizeof(Bucket) * bucket_num);
		memset(key_stores, 0, sizeof(key_stores));
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
			memcpy(key_stores[pos][min_counter], key, KEY_LENGTH_13);
			return 0;
		}

		uint32_t guard_val = buckets[pos].val[MAX_VALID_COUNTER];
		guard_val = UPDATE_GUARD_VAL(guard_val);


		if(!JUDGE_IF_SWAP(min_counter_val, guard_val))
		{
			buckets[pos].val[MAX_VALID_COUNTER] = guard_val;
			return 2;
		}


		memcpy(swap_key, key_stores[pos][min_counter], KEY_LENGTH_13);
		swap_val = buckets[pos].val[min_counter];

		buckets[pos].val[MAX_VALID_COUNTER] = 0;

		buckets[pos].key[min_counter] = fp;
		memcpy(key_stores[pos][min_counter], key, KEY_LENGTH_13);

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
			//return 32 if input is zero;
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
			memcpy(key_stores[pos][min_counter], key, KEY_LENGTH_13);
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
		memcpy(key_stores[pos][min_counter], key, KEY_LENGTH_13);
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
		fp ^= *((uint32_t*)(key + 4));
		fp ^= *((uint32_t*)(key + 8));
		uint32_t tmp_val = *((uint32_t*)(key + 9)) & 0x000000FF;
		fp ^= (tmp_val + (tmp_val << 8) + (tmp_val << 16) + (tmp_val << 24));


		return CalculateBucketPos(fp) % bucket_num;
	}

public:
	int get_memory_usage()
	{
		return bucket_num * COUNTER_PER_BUCKET * (8 + KEY_LENGTH_13);
	}
	int get_bucket_num()
	{
		return bucket_num;
	}
};








#endif