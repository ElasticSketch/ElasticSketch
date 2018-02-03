#ifndef __SETUP_H_
#define __SETUP_H_

#include <unordered_map>
#include <string>
#include <stdint.h>

// #define _BIND_THREAD_WITH_CPU_
int CPU_CORE_NO[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

/* thread setups */
#define THREAD_NUM 4

/* for read in file */
struct FIVE_TUPLE{	char key[13];	};
typedef vector<FIVE_TUPLE> TRACE;

typedef unordered_map<string, uint32_t> KEY_VAL;
typedef unordered_map<string, uint32_t>::iterator KEY_VAL_ITER;


#define TEST_NUM 11
int START_FILE_NO = 1;
int END_FILE_NO = 1;

char src_dir[100] = "../20160121/5s/";

TRACE traces[TEST_NUM];

void ReadInTraces(const char *trace_prefix)
{
	for(int datafileCnt = START_FILE_NO; datafileCnt <= END_FILE_NO; ++datafileCnt)
	{
		char datafileName[100];
		sprintf(datafileName, "%s%d.dat", trace_prefix, datafileCnt - 1);
		FILE *fin = fopen(datafileName, "rb");

		FIVE_TUPLE tmp_five_tuple;
		traces[datafileCnt - 1].clear();
		while(fread(&tmp_five_tuple, 1, 13, fin) == 13)
		{
			traces[datafileCnt - 1].push_back(tmp_five_tuple);
		}
		fclose(fin);

		printf("Successfully read in %s, %ld packets\n", datafileName, traces[datafileCnt - 1].size());
	}
	printf("\n");
}


#define TOTAL_MEM_IN_BYTES (16 * 1024 * 1024 / THREAD_NUM)
#define LS_HEAVY_PART_MEM (512 * 1024 / THREAD_NUM)
#define LS_BUCKET_NUM_4 (LS_HEAVY_PART_MEM / 64)
#define LS_BUCKET_NUM_13 (LS_HEAVY_PART_MEM / 168)


#define SK_D 3



#define test_cycles 1


#endif