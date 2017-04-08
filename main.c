#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip_vs.h>


struct dst_exthdr {
    __u8    nexthdr;
    __u8    hdrlen;
    __u8    opttype;
    __u8    optdatalen;
    __u8    geotype;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8   res:5,
	   t:1,
	   a:1,
	   l:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8   res:5,
           l:1,
	   a:1,
	   t:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    __u16   intpart;
    __u32   latfracpart;
    __u32   lonfracpart;
    __u32   alt1;
    __u32   alt2;
    __u32   sec;
    __u32   usec;
} __attribute__((packed));

static unsigned
int handle_tx_pkt(void *priv,
		  struct sk_buff *skb,
		  const struct nf_hook_state *state)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);

	if ((iph->nexthdr != NEXTHDR_DEST) &&
		((iph->nexthdr == NEXTHDR_TCP) || (iph->nexthdr == NEXTHDR_UDP))){
/*
		pr_info("%s\n", __func__);

		pr_info("nexthdr: %x\n", iph->nexthdr);
		pr_info("ip src: %pI6\n", &iph->saddr);
		pr_info("ip dst: %pI6\n", &iph->daddr);
*/
	}

	return NF_ACCEPT;
}


static unsigned
int handle_rx_pkt(void *priv,
		  struct sk_buff *skb,
		  const struct nf_hook_state *state)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);

	// catch destination option header
	if (ip6h->nexthdr == NEXTHDR_DEST) {
		struct dst_exthdr *deh = (struct dst_exthdr *)
			(skb->data + sizeof(struct ipv6hdr));

		pr_info("func:%s, ipv6->nexthdr:%x\n", __func__, ip6h->nexthdr);
		pr_info("func:%s, dsthdr->nexthdr:%x, dsthdr->hdrlen:%x\n",
			__func__, deh->nexthdr, deh->hdrlen);
		pr_info("opttype: %x\n", deh->opttype);
		pr_info("optdatalen: %x\n", deh->optdatalen);
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops tx_hook_ops = {
	.hook     = handle_tx_pkt,
	.pf       = PF_INET6,
	.hooknum  = NF_INET_LOCAL_OUT,
	.priority = NF_IP6_PRI_FILTER,
};

static struct nf_hook_ops rx_hook_ops = {
	.hook     = handle_rx_pkt,
	.pf       = PF_INET6,
	.hooknum  = NF_INET_LOCAL_IN,
	.priority = NF_IP6_PRI_FILTER,
};

static int  __init geov6_init(void)
{
	int ret;

	pr_info("%s\n", __func__);

	ret = nf_register_hook(&tx_hook_ops);
	if (ret < 0)
		return ret;

	ret = nf_register_hook(&rx_hook_ops);
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit geov6_exit(void)
{
	pr_info("%s\n", __func__);

	nf_unregister_hook(&tx_hook_ops);
	nf_unregister_hook(&rx_hook_ops);
}

module_init(geov6_init);
module_exit(geov6_exit);

MODULE_AUTHOR("KIMOTO Mizuki");
MODULE_DESCRIPTION("Kernel module for extension ipv6 header");
MODULE_LICENSE("GPL");
