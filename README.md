## Why to do

- 需要统计zk的事物日志
- zk自带的事物日志信息太少，不够实时
- 需要统计每个请求的耗时和返回状态码
- 需要统计每个事物的请求数和QPS
- 需要统计每个node的QPS和事物操作

## What is this

- zookeepr抓包工具，并把包解析成事物日志
- 满足上面的所有需求
- 便于问题定位和资源监控

## How to use

```
###### read data from device
# ./zk-sniffer -port=4181 -device=eth0
###### read data from pcap file
# ./zk-sniffer -port=4181 -file=1.pcap
```

## Screenshot

![](http://wx4.sinaimg.cn/mw690/6f6a4381ly1fcjaly09eej213e0hkgxg.jpg)

## Reference

- [https://github.com/twitter/zktraffic](https://github.com/twitter/zktraffic)
- [https://github.com/samuel/go-zookeeper](https://github.com/samuel/go-zookeeper)


