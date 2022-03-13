# 1 udp 测试
## 1.1 udp 发包时是否会发生阻塞
### 1.1.1 环境
```
/* 内核版本 */
root@young-VirtualBox:socket# uname -a
Linux young-VirtualBox 4.15.0-171-generic #180-Ubuntu SMP Wed Mar 2 17:25:05 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```
```
/*
 * ARP 队列可容纳的报文个数及字节数
 */
root@young-VirtualBox:socket# cat /proc/sys/net/ipv4/neigh/enp0s8/unres_qlen
101
root@young-VirtualBox:socket# cat /proc/sys/net/ipv4/neigh/enp0s8/unres_qlen_bytes 
212992
```
```
/*
 * 路由表
 */
root@young-VirtualBox:socket# ip r show
default via 10.0.2.2 dev enp0s3 proto dhcp metric 20100 
10.0.2.0/24 dev enp0s3 proto kernel scope link src 10.0.2.15 metric 100 
10.10.25.0/24 dev enp0s8 proto kernel scope link src 10.10.25.1 
169.254.0.0/16 dev enp0s8 scope link metric 1000 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
root@young-VirtualBox:socket#
```
### 1.1.2 测试
```
/*
 * 将 socket 队列阈值 (sk->sk_sndbuf) 设置为较小值 1000 (小于 arp 队列阈值)
 * 给不存在的 IP 发送 udp 报文
 * 每个报文1000字节 (UDP数据部分)，连续发送 100
 * 通过时间戳可以看到，发送第三个报文时出现了阻塞
 * 		-- 这符合预期，即
 */
root@young-VirtualBox:socket# ./udp_client -p 3456 -S 1000 -s 1000 -r 10.0.2.100 -dd -c 100
UDP sendbuf: 212992 -> 4608 (expected: 1000)
Prepare to send packet to 10.0.2.100:3456
send 1000 bytes udp data to server @1647180175
send 1000 bytes udp data to server @1647180175

send 1000 bytes udp data to server @1647180178
send 1000 bytes udp data to server @1647180178

send 1000 bytes udp data to server @1647180181
send 1000 bytes udp data to server @1647180181

^CStatistics:
        xmitted pkt :           7
        received pkt:           0
```
## 1.2 udp 发包时阻塞模式会怎样
### 1.2.1 环境
```
环境同上
```
### 1.2.2 测试
```
/*
 * 比上面的测试多了个 -n 参数 (-n 表示为非阻塞模式)
 * 可以看到返回了错误11，即 EAGAIN
 *			-- 这也符合预期，即
 */
root@young-VirtualBox:socket# ./udp_client -p 3456 -S 1000 -s 1000 -r 10.0.2.100 -dd -c 100 -n
UDP sendbuf: 212992 -> 4608 (expected: 1000)
set udp socket to non-block mode
Prepare to send packet to 10.0.2.100:3456
send 1000 bytes udp data to server @1647180186
send 1000 bytes udp data to server @1647180186
failed to exec sendto: Resource temporarily unavailable @11
```
## 1.3 相关代码
### 1.3.1 arp 队列
```
/*
 * 当队列中报文字节数大于阈值时，则会将老的 skb 释放
 /
__neigh_event_send			in net/core/neighbour.c
	if (neigh->nud_state == NUD_INCOMPLETE) {
		if (skb) {
			while (neigh->arp_queue_len_bytes + skb->truesize >
			       NEIGH_VAR(neigh->parms, QUEUE_LEN_BYTES)) {
				struct sk_buff *buff;

				buff = __skb_dequeue(&neigh->arp_queue);
				if (!buff)
					break;
				neigh->arp_queue_len_bytes -= buff->truesize;
				kfree_skb(buff);
				NEIGH_CACHE_STAT_INC(neigh->tbl, unres_discards);
			}
			skb_dst_force(skb);
			__skb_queue_tail(&neigh->arp_queue, skb);
			neigh->arp_queue_len_bytes += skb->truesize;
		}
		rc = 1;
	}
```
### 1.3.2 
```
udp_sendmsg
	-> ip_make_skb
		-> err = __ip_append_data()
			-> sock_alloc_send_skb
				-> sock_alloc_send_pskb
		-> if (err) {
			__ip_flush_pending_frames()
			return ERR_PTR(err);
		-> }

		-> return __ip_make_skb()
```
```
sock_alloc_send_pskb
	-> timeo = sock_sndtimeo(sk, noblock)
	-> for (;;) {
		/*
		 * 若当前 socket 使用内存未达到阈值，则跳出循环
		 * 后续分配 skb
		 */
		-> if (sk_wmem_alloc_get(sk) < READ_ONCE(sk->sk_sndbuf))
			break
		/*
		 * 否则，若是非阻塞模式，则直接返回 EAGAIN
		 */
		-> err = -EAGAIN
		-> if (!timeo)
			goto failure
		-> if (signal_pending(current))
			goto interrupted
		/*
		 * 阻塞模式，一直等待，直到内存统计 (sk->sk_wmem_alloc) 减小到阈值以下要求
		 * 			-- 阈值之所以会减小，是因为 ARP 模块一定时间内 mac 学习失败，将 skb 释放
		 *			-- 从而 sk->sk_wmem_alloc 统计也减小了
		 */
		-> timeo = sock_wait_for_wmem(sk, timeo)
	-> }
	
	->skb = alloc_skb_with_frags(header_len, data_len, max_page_order,
			   errcode, sk->sk_allocation);
	-> if (skb)
		skb_set_owner_w(skb, sk);
	-> return skb;
```
### 1.3.3
```
/*
 * 释放 skb 时，相应的计数也要减少
 */
kfree_skb
	-> __kfree_skb
		-> skb_release_all
			-> skb_release_head_state
				/* skb->destructor  */
				-> sock_wfree
					-> refcount_sub_and_test(len, &sk->sk_wmem_alloc)
```