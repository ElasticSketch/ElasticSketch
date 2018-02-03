# ElasticSketch

## Directory
- `elastic_sketch_technical_report` can help you understand the paper better.
- `data`: traces for test, each 13 bytes in a trace is a (SrcIP:SrcPort, DstIP:DstPort, protocol)
- `src` directory contains source codes
  - `code`: Elastic sketch and other algorithms implemented on CPU
  - `FPGA`: Elastic sketch implemented on FPGA
  - `MultiCore`: Elastic sketch using multi-core
  - `OVS`: Elastic sketch implemented on OVS
- more details can be found in above directories

## How to make
- cd `./src`
- `$ make`

