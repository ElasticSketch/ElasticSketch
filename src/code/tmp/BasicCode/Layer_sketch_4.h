#ifndef _LAYER_SKETCH_4_H_
#define _LAYER_SKETCH_4_H_

#include "param.h"
#include "Elephant_part_4.h"
#include "Mice_part_4.h" 


template<int bucket_num, int tot_memory_in_bytes>
class LayerSketch_4
{
public:
	static constexpr int elephant_mem = bucket_num * COUNTER_PER_BUCKET * 8;
	static constexpr int mice_mem = tot_memory_in_bytes - elephant_mem;
	
	ElephantPart_4<bucket_num> elephant_part;
	MicePart_4<mice_mem> mice_part;

	LayerSketch_4(){
		// printf("elephant: %d\tmice_counter:%d\n", bucket_num + 1, mice_mem);
	}
	~LayerSketch_4(){}
	void clear()
	{
		elephant_part.clear();
		mice_part.clear();
	}

	void insert(uint8_t *key, int f = 1)
	{
		uint8_t swap_key[KEY_LENGTH_4];
		uint32_t swap_val = 0;
		int result = elephant_part.insert(key, swap_key, swap_val, f);
		
		switch(result)
		{
			case 0: return;
			case 1:{
				if(HIGHEST_BIT_IS_1(swap_val))
					mice_part.insert(swap_key, GetCounterVal(swap_val));
				else
					mice_part.swap_insert(swap_key, swap_val);
				return;
				// mice_part.insert(swap_key, GetCounterVal(swap_val));
			}
			case 2:	mice_part.insert(key, 1);	return;
			default:	printf("error return value !\n");	exit(1);
		}
	}

	void quick_insert(uint8_t *key, int f = 1)
	{
		elephant_part.quick_insert(key, f);
	}

	int query(uint8_t *key)
	{
		uint32_t elephant_result = elephant_part.query(key);

		if(elephant_result == 0 || HIGHEST_BIT_IS_1(elephant_result))
		{
			int mice_result = mice_part.query(key);
			return (int)GetCounterVal(elephant_result) + mice_result;
		}
		return (int)elephant_result;
	}


	int query_compressed_part(uint8_t *key, uint8_t *compress_part, int compress_counter_num)
	{
		uint32_t elephant_result = elephant_part.query(key);
		if(elephant_result == 0 || HIGHEST_BIT_IS_1(elephant_result))
		{
			int mice_result = mice_part.query_compressed_part(key, compress_part, compress_counter_num);
			return (int)GetCounterVal(elephant_result) + mice_result;
		}
		return (int)elephant_result;
	}

public:

	string name = "LS_4";

	int get_compress_width(int ratio)
	{
		return mice_part.get_compress_width(ratio);
	}
	void compress(int ratio, uint8_t *dst)
	{
		mice_part.compress(ratio, dst);
	}
	int get_bucket_num()
	{
		return elephant_part.get_bucket_num();
	}
	double get_bandwidth(int compress_ratio)
	{
		int result = elephant_part.get_memory_usage();
		result += get_compress_width(compress_ratio) * sizeof(uint8_t);
		return result * 1.0 / 1024 / 1024;
	}

	int count_high_1_bits()
	{
		return elephant_part.count_high_1_bits();
	}

public:
	void *operator new(size_t sz)
	{
		constexpr uint32_t alignment = 64;
		size_t alloc_size = (2 * alignment + sz) / alignment * alignment;
		void * ptr = ::operator new(alloc_size);
		void * old_ptr = ptr;
		void * new_ptr = ((char*)std::align(alignment, sz, ptr, alloc_size) + alignment);
		((void **)new_ptr)[-1] = old_ptr;

		return new_ptr;
	}

	void operator delete(void * p)
	{
		::operator delete(((void **)p)[-1]);
	}
};





#endif