## FPGA implementation

# Overall design
 				
| ip_addrress --> | heavy_part_table0 | heavy_part_table1 | heavy_part_table2| heavy_part_table3 | light_part_table |
| :-: | :-: | :-: | :-: | :-: | -: |
				
- In each of heavy_part_table0, heavy_part_table1, heavy_part_table2 and heavy_part_table3, there is a RAM (width:96bits, depth:4096). 
- The light part contains a RAM (width:8bit, depth:2^19). 
- Every table has its own FIFO queue to buffer ip addresses from upper module, making the procedure can be pipelined.
