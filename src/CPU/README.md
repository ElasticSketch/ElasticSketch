# CPU CODE

For each measurement task, besides Elastic sketch, we have implemented many other algorithms:
- `flow size estimation`: CM sketch, CU sketch, Count sketch.
- `heavy hitter detection`: SpaceSaving, Count/CM sketch with a min-heap (CountHeap/CMHeap), UnivMon, Hashpipe. 
- `heavy change detection`: Revisible sketch, FlowRadar, UnivMon.
- `flow size distribution`: MRAC
- `entropy`: UnivMon, Sieving.
- `cardinality`: Linear counting, UnivMon.

## How to make and test
First `make` in `demo`, and then you can test the above algorithms.

