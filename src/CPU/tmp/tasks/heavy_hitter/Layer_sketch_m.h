#ifndef _LAYER_SKETCH_4_M_
#define _LAYER_SKETCH_4_M_

#include "param.h"
#include "Elephant_part_m.h"
#include "Mice_part_m.h"


class LayerSketch_4
{
	int elephant_mem;
	int mice_mem;
	int tot_memory_in_bytes;
	int bucket_num;
	
	ElephantPart_4 * elephant_part;
	MicePart_4 * mice_part;

public:
	LayerSketch_4(int bucket_num_, int tot_memory_in_bytes_): bucket_num(bucket_num_), tot_memory_in_bytes(tot_memory_in_bytes_)
	{
		elephant_mem = bucket_num * COUNTER_PER_BUCKET * 8;
		mice_mem = tot_memory_in_bytes - elephant_mem-1;
		elephant_part = new ElephantPart_4(bucket_num);
		mice_part = new MicePart_4(mice_mem);
		// printf("elephant: %d\tmice_counter:%d\n", bucket_num + 1, mice_mem);
	}
	~LayerSketch_4()
	{
		delete elephant_part;
		delete mice_part;
	}
	void clear()
	{
		elephant_part->clear();
		mice_part->clear();
	}

	void insert(uint8_t *key, int f = 1)
	{
		uint8_t swap_key[KEY_LENGTH_4];
		uint32_t swap_val = 0;
		int result = elephant_part->insert(key, swap_key, swap_val, f);
		
		switch(result)
		{
			case 0: return;
			case 1:{
				if(HIGHEST_BIT_IS_1(swap_val))
					mice_part->insert(swap_key, GetCounterVal(swap_val));
				else
					mice_part->swap_insert(swap_key, swap_val);
				return;
				// mice_part->insert(swap_key, GetCounterVal(swap_val));
			}
			case 2:	mice_part->insert(key, 1);	return;
			default:	printf("error return value !\n");	exit(1);
		}
	}

	void quick_insert(uint8_t *key, int f = 1)
	{
		elephant_part->quick_insert(key, f);
	}

	int query(uint8_t *key)
	{
		uint32_t elephant_result = elephant_part->query(key);

		if(elephant_result == 0 || HIGHEST_BIT_IS_1(elephant_result))
		// if(elephant_result == 0)
		{
			int mice_result = mice_part->query(key);
			return (int)GetCounterVal(elephant_result) + mice_result;
		}
		return (int)elephant_result;
	}
	
	void query_key(uint8_t *key)
	{
		uint32_t elephant_result = elephant_part->query(key);

		printf("sign: %d %d\n", HIGHEST_BIT_IS_1(elephant_result), elephant_result);
		if(HIGHEST_BIT_IS_1(elephant_result))
		// if(elephant_result == 0)
		{
			int mice_result = mice_part->query(key);
			printf("mice: %d\n", mice_result);
		}
	}

	int query_compressed_part(uint8_t *key, uint8_t *compress_part, int compress_counter_num)
	{
		uint32_t elephant_result = elephant_part->query(key);
		if(elephant_result == 0 || HIGHEST_BIT_IS_1(elephant_result))
		// if(elephant_result == 0)
		{
			int mice_result = mice_part->query_compressed_part(key, compress_part, compress_counter_num);
			return (int)GetCounterVal(elephant_result) + mice_result;
		}
		return (int)elephant_result;
	}

public:

	string name = "LS_4";

	int get_compress_width(int ratio)
	{
		return mice_part->get_compress_width(ratio);
	}
	void compress(int ratio, uint8_t *dst)
	{
		mice_part->compress(ratio, dst);
	}
	int get_bucket_num()
	{
		return elephant_part->get_bucket_num();
	}
	double get_bandwidth(int compress_ratio)
	{
		int result = elephant_part->get_memory_usage();
		result += get_compress_width(compress_ratio) * sizeof(uint8_t);
		return result * 1.0 / 1024 / 1024;
	}

public:
	void get_heavy_hitter(uint32_t threshold, std::vector<pair<string, uint32_t> >& ret)
    {
    	std::vector<pair<string, uint32_t> > elephant;
    	std::vector<pair<string, uint32_t> >::iterator it;
    	elephant.clear();
    	ret.clear();
    	elephant_part->dump(elephant);
    	//printf("dump: %d\n", elephant.size());
    	for(it = elephant.begin(); it != elephant.end(); ++it)
		{
			uint32_t val;
    		uint32_t elephant_result = (*it).second;
    		int mice_result = 0;
    		if(HIGHEST_BIT_IS_1(elephant_result))
			{
				char key[13];
				strcpy(key, ((*it).first).c_str());
				mice_result = mice_part->query((unsigned char*)key);
				val = GetCounterVal(elephant_result) + mice_result;
				//if(val >= threshold) printf("%s, %d, %d\n", ((*it).first).c_str(), val, mice_result);
			}
			else val = elephant_result;
			if(val >= threshold)
			{
				ret.push_back(make_pair((*it).first, val));	
			}
		}
		//printf("size: %d\n", ret.size());
	}
	void get_heavy_hitter_compress(uint32_t threshold, std::vector<pair<string, uint32_t> >& ret, uint8_t * compress_part, int width)
    {
    	std::vector<pair<string, uint32_t> > elephant;
    	std::vector<pair<string, uint32_t> >::iterator it;
    	elephant.clear();
    	ret.clear();
    	elephant_part->dump(elephant);
    	//printf("dump: %d\n", elephant.size());
    	for(it = elephant.begin(); it != elephant.end(); ++it)
		{
			uint32_t val;
    		uint32_t elephant_result = (*it).second;
    		int mice_result = 0;
    		if(HIGHEST_BIT_IS_1(elephant_result))
			{
				char key[13];
				strcpy(key, ((*it).first).c_str());
				mice_result = mice_part->query_compressed_part((unsigned char*)key, compress_part, width);
				val = GetCounterVal(elephant_result) + mice_result;
				//if(val >= threshold) printf("%s, %d, %d\n", ((*it).first).c_str(), val, mice_result);
			}
			else val = elephant_result;
			if(val >= threshold)
			{
				ret.push_back(make_pair((*it).first, val));	
				if(val == 0) printf("wrong:%d\n", val);			
			}
		}
		//printf("size: %d\n", ret.size());
	}
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
