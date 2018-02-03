#ifndef _MICE_PART_13_H_
#define _MICE_PART_13_H_

#include "param.h"

template<int init_mem_in_bytes>
class MicePart_13
{
	static constexpr uint32_t counter_num = init_mem_in_bytes;
	BOBHash32 *bobhash = NULL;
public:
	uint8_t counters[counter_num];

	MicePart_13()
	{
		memset(counters, 0, counter_num);

		std::random_device rd;
		bobhash = new BOBHash32(rd() % MAX_PRIME32);
	}
	~MicePart_13()
	{
		delete bobhash;
	}
	void clear()
	{
		memset(counters, 0, counter_num);
	}

	void insert(uint8_t *key, int f = 1)
	{
		uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, KEY_LENGTH_13);
		uint32_t pos = hash_val % (uint32_t)counter_num;

		int new_val = (int)counters[pos] + f;
		new_val = new_val < 255 ? new_val : 255;
		counters[pos] = (uint8_t)new_val;
	}

	void swap_insert(uint8_t *key, int f)
	{
		uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, KEY_LENGTH_13);
		uint32_t pos = hash_val % (uint32_t)counter_num;

		f = f < 255 ? f : 255;
		if(counters[pos] < f)
			counters[pos] = (uint8_t)f;
	}

	int query(uint8_t *key)
	{
		uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, KEY_LENGTH_13);
		uint32_t pos = hash_val % (uint32_t)counter_num;

		return (int)counters[pos];
	}

public:
	void compress(int ratio, uint8_t *dst)
	{
		int width = get_compress_width(ratio);

		for(int i = 0; i < width && i < counter_num; ++i)
		{
			uint8_t max_val = 0;
			for(int j = i; j < counter_num; j += width)
				max_val = counters[j] > max_val ? counters[j] : max_val;
			dst[i] = max_val;
		}
	}

	int query_compressed_part(uint8_t *key, uint8_t *compress_part, int compress_counter_num)
	{
		uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, KEY_LENGTH_13);
		uint32_t pos = (hash_val % (uint32_t)counter_num) % compress_counter_num;

		return (int)compress_part[pos];
	}


public:
	int get_compress_width(int ratio)
	{
		return (counter_num / ratio);
	}
	int get_compress_memory(int ratio)
	{
		return (uint32_t)(counter_num / ratio);
	}
	int get_memory_usage()
	{
		return counter_num;
	}

};




#endif


















