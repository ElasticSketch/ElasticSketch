# ElasticSketch

## Introduction
When network is undergoing problems such as congestion, scan attack, DDoS attack, etc., measurements are much more important than usual. In this case, traffic characteristics including available bandwidth, packet rate, and flow size distribution vary drastically, significantly degrading the performance of measurements. To address this issue, we propose the Elastic sketch. It is adaptive to currently traffic characteristics. Besides, it is generic to measurement tasks and platforms. We implement the Elastic sketch on six platforms: P4, FPGA, GPU, CPU, multi-core CPU, and OVS, to process six typical measurement tasks. Experimental results and theoretical analysis show that the Elastic sketch can adapt well to traffic characteristics. Compared to the state-of-the-art, the Elastic sketch achieves 44.6 ∼ 45.2 times faster speed and 2.0 ∼ 273.7 smaller error rate.

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

